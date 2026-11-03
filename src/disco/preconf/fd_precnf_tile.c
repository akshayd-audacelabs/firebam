#define _GNU_SOURCE
/* fd_precnf_tile forwards a copy of verified, deduplicated non-vote
   transactions to an external pre-confirmation relayer.

   The tile reads dedup_resolv (dedup_resolh in Frankendancer) as an
   UNRELIABLE consumer, copies and classifies every frag, and encodes
   forwardable transactions into RelayUpdate batches queued in an
   fd_circq.  A batch is flushed to the
   queue once it holds FD_PRECNF_BATCH_TXN_MAX transactions or
   FD_PRECNF_FLUSH_NS after its first transaction.  fd_precnf_client
   authenticates with the relayer, keeps the StartRelayStream request
   open and sends the queue.  While the stream is not open, transactions
   are dropped instead of queued.

   Jito bundles are forwarded whole, as RelayUpdate bundle messages
   carrying the block engine's bundle UUID.  fd_txn_m_t only carries the
   bundle tile's sequence number (block_engine.bundle_id), so the bundle
   tile also publishes (bundle_seq, uuid) on bundle_precnf just before
   each bundle's transactions.  All bundles pass through verify:0 and the
   single dedup tile, so a bundle's transactions arrive in order and
   bundles never interleave (other transactions may appear in between).
   verify and dedup drop the rest of a bundle after a failure, so a
   bundle that does not complete before the next one starts is dropped,
   never sent in part.  BAM transactions are never treated as bundles,
   even though atomic BAM batches also set block_engine.bundle_id.

   The input link is unreliable so that this tile can never backpressure
   dedup (and through it, block packing).  If the tile falls behind, the
   frags it missed are overwritten and counted as overruns by stem.
   Because of that, frag data must be copied out in during_frag; stem
   only calls after_frag if the copy was not torn by an overrun.  The
   same holds for bundle_precnf. */

#include "../topo/fd_topo.h"
#include "../fd_txn_m.h"
#include "../bundle/fd_bundle_tile.h"
#include "../bam/fd_bam_vote.h"
#include "../metrics/fd_metrics.h"
#include "../keyguard/fd_keyload.h"
#include "../keyguard/fd_keyswitch.h"
#include "../keyguard/fd_keyguard_client.h"
#include "../sleep/fd_sleep.h"
#include "../events/fd_circq.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../tango/tempo/fd_tempo.h"
#include "fd_precnf_encode.h"
#include "fd_precnf_client.h"
#include "../waker/fd_waker.h"
#include "../../waltz/resolv/fd_netdb.h"
#include "../../waltz/http/fd_url.h"
#include "../../ballet/x509/fd_x509_ca_store.h"

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <linux/futex.h>
#include "generated/fd_precnf_tile_seccomp.h"

#define IN_KIND_DEDUP       (0)
#define IN_KIND_BUNDLE_UUID (1)

/* Bundle UUIDs are kept in a direct-mapped table indexed by bundle_seq.
   A UUID is published before its bundle's transactions, which still
   have to pass verify and dedup, so it only needs to survive the bundles
   in flight between the two (bundle_seq starts at 1, so the zeroed table
   matches nothing). */
#define FD_PRECNF_UUID_TABLE_CNT (4096UL)
FD_STATIC_ASSERT( !(FD_PRECNF_UUID_TABLE_CNT & (FD_PRECNF_UUID_TABLE_CNT-1UL)), uuid_table_pow2 );
FD_STATIC_ASSERT( FD_PRECNF_BUNDLE_UUID_MAX==FD_BUNDLE_UUID_MAX, uuid_max );

/* A partially received bundle older than this is dropped.  Normally
   the next bundle drops it first; this only keeps the metric honest
   when no other bundle follows. */
#define FD_PRECNF_BUNDLE_TIMEOUT_NS (1000000000L) /* 1 s */

/* Max time a transaction waits in an open batch before it is flushed.
   Small compared to network latency, but lets bursts share a message. */
#define FD_PRECNF_FLUSH_NS (100000L) /* 100 us */

/* Size of the queue of encoded messages waiting to be sent.  When full,
   the oldest messages are evicted. */
#define FD_PRECNF_CIRCQ_SZ (64UL<<20) /* 64 MiB */

/* gRPC client buffer size.  Bounds the largest message, so it must fit
   a full batch (FD_PRECNF_BATCH_ENC_MAX) with HTTP/2 framing. */
#define FD_PRECNF_GRPC_BUF_MAX (2UL<<20) /* 2 MiB */
FD_STATIC_ASSERT( FD_PRECNF_BATCH_ENC_MAX+5UL+9UL*((FD_PRECNF_BATCH_ENC_MAX+5UL+16383UL)/16384UL)<=FD_PRECNF_GRPC_BUF_MAX, batch_fits_grpc_buf );
FD_STATIC_ASSERT( FD_PRECNF_BUNDLE_BATCH_ENC_MAX+5UL+9UL*((FD_PRECNF_BUNDLE_BATCH_ENC_MAX+5UL+16383UL)/16384UL)<=FD_PRECNF_GRPC_BUF_MAX, bundle_batch_fits_grpc_buf );

struct fd_precnf_tile_in {
  fd_wksp_t * mem;
  ulong       mtu;
  ulong       chunk0;
  ulong       wmark;
};

typedef struct fd_precnf_tile_in fd_precnf_tile_in_t;

struct fd_precnf_tile {
  fd_keyswitch_t *     keyswitch;
  uchar                identity_pubkey[ 32UL ];
  fd_keyguard_client_t keyguard_client[1];

  ulong               in_cnt;
  int                 in_kind[ 64UL ];
  fd_precnf_tile_in_t in[ 64UL ];

  /* Copy of the frag currently being processed.  Holds the fd_txn_m_t
     header, the raw transaction payload and the parsed fd_txn_t. */
  ulong frag_sz;
  uchar frag[ FD_TPU_PARSED_MTU ] __attribute__((aligned(alignof(fd_txn_m_t))));

  /* Encoded messages waiting to be sent. */
  fd_circq_t * circq;

  /* Relayer connection. */
  fd_precnf_client_t * client;
  fd_rng_t             rng[1];
  ulong                seed;
  int                  use_tls;
  fd_netdb_fds_t       netdb_fds[1];
  fd_x509_ca_store_t   ca_store[1]; /* loaded in privileged_init */

  ulong   waker_client_idx;
  ulong * waker_fseq;
  long    next_poll_deadline; /* wallclock ns */
  ulong   idle_cnt;
  double  tick_per_ns;

  /* The batch being built.  batch_first_tick is the tickcount when its
     first transaction was added (meaningless while empty). */
  fd_precnf_batch_t batch[1];
  long              batch_first_tick;
  long              flush_ticks;

  /* Bundle UUIDs from the bundle tile, by bundle_seq. */
  fd_bundle_uuid_t uuids[ FD_PRECNF_UUID_TABLE_CNT ];

  /* The Jito bundle being received.  bundle_id is its
     block_engine.bundle_id (0 before the first bundle).  bundle_closed
     is set once it was completed or dropped: further transactions with
     the same id are ignored. */
  ulong              bundle_id;
  ulong              bundle_txn_cnt; /* expected */
  int                bundle_closed;
  long               bundle_first_tick;
  long               bundle_timeout_ticks;
  fd_precnf_bundle_t bundle[1];

  /* Complete bundles waiting to be encoded, flushed like batch. */
  fd_precnf_bundle_batch_t bundle_batch[1];
  long                     bundle_batch_first_tick;

  struct {
    ulong txn_classified[ FD_METRICS_ENUM_PRECNF_TXN_CLASS_CNT ];
    ulong vote_skipped;
    ulong bam_preprocess_failed_skipped;
    ulong batches_queued;
    ulong packets_queued;
    ulong bytes_queued;
    ulong txn_dropped_not_streaming;
    ulong bundle_uuid_received;
    ulong bundles_queued;
    ulong bundle_batches_queued;
    ulong bundle_packets_queued;
    ulong bundle_dropped[ FD_METRICS_ENUM_PRECNF_BUNDLE_DROP_REASON_CNT ];
  } metrics;
};

typedef struct fd_precnf_tile fd_precnf_tile_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_ulong_max( fd_ulong_max( alignof( fd_precnf_tile_t ), fd_circq_align() ), fd_precnf_client_align() );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_precnf_tile_t ), sizeof( fd_precnf_tile_t )                  );
  l = FD_LAYOUT_APPEND( l, fd_circq_align(),            fd_circq_footprint( FD_PRECNF_CIRCQ_SZ ) );
  l = FD_LAYOUT_APPEND( l, fd_precnf_client_align(),    fd_precnf_client_footprint( FD_PRECNF_GRPC_BUF_MAX ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
metrics_write( fd_precnf_tile_t * ctx ) {
  FD_MCNT_ENUM_COPY( PRECNF, TXN_CLASSIFIED,                ctx->metrics.txn_classified                );
  FD_MCNT_SET(       PRECNF, VOTE_SKIPPED,                  ctx->metrics.vote_skipped                  );
  FD_MCNT_SET(       PRECNF, BAM_PREPROCESS_FAILED_SKIPPED, ctx->metrics.bam_preprocess_failed_skipped );
  FD_MCNT_SET(       PRECNF, BATCH_QUEUED,                ctx->metrics.batches_queued                );
  FD_MCNT_SET(       PRECNF, PACKET_QUEUED,                ctx->metrics.packets_queued                );
  FD_MCNT_SET(       PRECNF, BYTES_QUEUED,                  ctx->metrics.bytes_queued                  );
  FD_MCNT_SET(       PRECNF, QUEUE_DROPPED,                 ctx->circq->metrics.drop_cnt               );
  FD_MGAUGE_SET(     PRECNF, QUEUE_COUNT,                   ctx->circq->cnt                            );
  FD_MGAUGE_SET(     PRECNF, QUEUE_BYTES,              fd_circq_bytes_used( ctx->circq )          );
  FD_MCNT_SET(       PRECNF, TXN_NO_STREAM_DROPPED,     ctx->metrics.txn_dropped_not_streaming     );
  FD_MCNT_SET(       PRECNF, BUNDLE_UUID_RECEIVED,          ctx->metrics.bundle_uuid_received          );
  FD_MCNT_SET(       PRECNF, BUNDLE_QUEUED,                ctx->metrics.bundles_queued                );
  FD_MCNT_SET(       PRECNF, BUNDLE_BATCH_QUEUED,         ctx->metrics.bundle_batches_queued         );
  FD_MCNT_SET(       PRECNF, BUNDLE_PACKET_QUEUED,         ctx->metrics.bundle_packets_queued         );
  FD_MCNT_ENUM_COPY( PRECNF, BUNDLE_DROPPED,                ctx->metrics.bundle_dropped                );

  fd_precnf_client_metrics_t const * cm = fd_precnf_client_metrics( ctx->client );
  fd_precnf_auther_t const *         am = fd_precnf_client_auther( ctx->client );
  FD_MGAUGE_SET(     PRECNF, CONN_STATE,        fd_precnf_client_state( ctx->client ) );
  FD_MCNT_SET(       PRECNF, CONN_ATTEMPTED,   cm->connect_attempt_cnt   );
  FD_MCNT_SET(       PRECNF, STREAM_OPENED,     cm->stream_open_cnt       );
  FD_MCNT_ENUM_COPY( PRECNF, DISCONNECTED,      cm->disconnect_cnt        );
  FD_MCNT_SET(       PRECNF, HEARTBEAT_SENT,    cm->heartbeat_sent_cnt    );
  FD_MCNT_SET(       PRECNF, MSG_SENT,          cm->msg_sent_cnt          );
  FD_MCNT_SET(       PRECNF, MSG_OVERSIZE_DROPPED,     cm->msg_too_large_cnt     );
  FD_MCNT_SET(       PRECNF, STALE_MSG_CLEARED, cm->stale_msg_cleared_cnt );
  FD_MCNT_SET(       PRECNF, RESPONSE_RECEIVED, cm->response_rx_cnt       );
  FD_MCNT_SET(       PRECNF, BYTES_WRITTEN,     cm->bytes_written         );
  FD_MCNT_SET(       PRECNF, BYTES_READ,        cm->bytes_read            );
  FD_MCNT_SET(       PRECNF, AUTH_SUCCEEDED,      am->auth_cnt              );
  FD_MCNT_SET(       PRECNF, AUTH_REFRESHED,      am->refresh_cnt           );
  FD_MCNT_SET(       PRECNF, AUTH_FAILED,       am->fail_cnt              );
}

/* flush_batch finishes the open batch (if any) and appends the encoded
   RelayUpdate to the send queue, evicting the oldest queued messages if
   the queue is full. */

static void
flush_batch( fd_precnf_tile_t * ctx ) {
  ulong txn_cnt = fd_precnf_batch_txn_cnt( ctx->batch );
  if( FD_LIKELY( !txn_cnt ) ) return;

  /* Size first, then encode directly into the queue. */
  long    now    = fd_log_wallclock();
  ulong   msg_sz = fd_precnf_batch_encoded_sz( ctx->batch, now );
  uchar * dst    = fd_circq_push_back( ctx->circq, 1UL, msg_sz );
  FD_TEST( dst ); /* only fails if msg_sz exceeds the whole queue */
  FD_TEST( fd_precnf_batch_encode( ctx->batch, now, dst, msg_sz )==msg_sz );

  ctx->metrics.batches_queued++;
  ctx->metrics.packets_queued += txn_cnt;
  ctx->metrics.bytes_queued   += msg_sz;
  fd_precnf_batch_init( ctx->batch );
  ctx->next_poll_deadline = 0L; /* let the client send it right away */
}

/* queue_txn adds a transaction to the open batch, flushing first if the
   batch is full. */

static void
queue_txn( fd_precnf_tile_t * ctx,
           fd_txn_m_t const * txnm ) {
  int was_empty = !fd_precnf_batch_txn_cnt( ctx->batch );
  if( FD_UNLIKELY( !fd_precnf_batch_append( ctx->batch, fd_txn_m_payload_const( txnm ), txnm->payload_sz, txnm->source_ipv4 ) ) ) {
    flush_batch( ctx );
    was_empty = 1;
    FD_TEST( fd_precnf_batch_append( ctx->batch, fd_txn_m_payload_const( txnm ), txnm->payload_sz, txnm->source_ipv4 ) );
  }
  if( was_empty ) ctx->batch_first_tick = fd_tickcount();
  if( FD_UNLIKELY( fd_precnf_batch_txn_cnt( ctx->batch )>=FD_PRECNF_BATCH_TXN_MAX ) ) flush_batch( ctx );
}

/* flush_bundle_batch is flush_batch for the bundle batch. */

static void
flush_bundle_batch( fd_precnf_tile_t * ctx ) {
  ulong bundle_cnt = fd_precnf_bundle_batch_cnt( ctx->bundle_batch );
  if( FD_LIKELY( !bundle_cnt ) ) return;

  long    now    = fd_log_wallclock();
  ulong   msg_sz = fd_precnf_bundle_batch_encoded_sz( ctx->bundle_batch, now );
  uchar * dst    = fd_circq_push_back( ctx->circq, 1UL, msg_sz );
  FD_TEST( dst );
  FD_TEST( fd_precnf_bundle_batch_encode( ctx->bundle_batch, now, dst, msg_sz )==msg_sz );

  ctx->metrics.bundle_batches_queued++;
  ctx->metrics.bundles_queued        += bundle_cnt;
  ctx->metrics.bundle_packets_queued += ctx->bundle_batch->txn_cnt;
  ctx->metrics.bytes_queued          += msg_sz;
  fd_precnf_bundle_batch_init( ctx->bundle_batch );
  ctx->next_poll_deadline = 0L;
}

static void
bundle_drop( fd_precnf_tile_t * ctx,
             ulong              reason ) {
  ctx->metrics.bundle_dropped[ reason ]++;
  ctx->bundle_closed = 1;
}

/* bundle_complete forwards the received bundle with its UUID. */

static void
bundle_complete( fd_precnf_tile_t * ctx ) {
  ctx->bundle_closed = 1;

  fd_bundle_uuid_t const * u = &ctx->uuids[ ctx->bundle_id & (FD_PRECNF_UUID_TABLE_CNT-1UL) ];
  if( FD_UNLIKELY( u->bundle_seq!=ctx->bundle_id ) ) {
    ctx->metrics.bundle_dropped[ FD_METRICS_ENUM_PRECNF_BUNDLE_DROP_REASON_V_UUID_MISSING_IDX ]++;
    return;
  }
  if( FD_UNLIKELY( u->txn_cnt!=ctx->bundle_txn_cnt ||
                   !fd_precnf_bundle_set_uuid( ctx->bundle, u->uuid, u->uuid_sz ) ) ) {
    ctx->metrics.bundle_dropped[ FD_METRICS_ENUM_PRECNF_BUNDLE_DROP_REASON_V_INVALID_IDX ]++;
    return;
  }

  /* As for single transactions: not queued while the stream is down. */
  if( FD_UNLIKELY( !fd_precnf_client_streaming( ctx->client ) ) ) {
    ctx->metrics.txn_dropped_not_streaming += ctx->bundle->txn_cnt;
    return;
  }

  if( FD_UNLIKELY( !fd_precnf_bundle_batch_append( ctx->bundle_batch, ctx->bundle ) ) ) {
    flush_bundle_batch( ctx );
    FD_TEST( fd_precnf_bundle_batch_append( ctx->bundle_batch, ctx->bundle ) );
  }
  if( fd_precnf_bundle_batch_cnt( ctx->bundle_batch )==1UL ) ctx->bundle_batch_first_tick = fd_tickcount();
  if( FD_UNLIKELY( fd_precnf_bundle_batch_cnt( ctx->bundle_batch )>=FD_PRECNF_BUNDLE_BATCH_MAX ) ) flush_bundle_batch( ctx );
}

/* bundle_txn handles one transaction of a Jito bundle. */

static void
bundle_txn( fd_precnf_tile_t * ctx,
            fd_txn_m_t const * txnm ) {
  ulong id = txnm->block_engine.bundle_id;
  if( FD_UNLIKELY( id!=ctx->bundle_id ) ) {
    /* A new bundle starts.  If the previous one is still open, some of
       its transactions never arrived. */
    if( FD_UNLIKELY( ctx->bundle_id && !ctx->bundle_closed ) )
      bundle_drop( ctx, FD_METRICS_ENUM_PRECNF_BUNDLE_DROP_REASON_V_PARTIAL_IDX );

    ctx->bundle_id         = id;
    ctx->bundle_txn_cnt    = txnm->block_engine.bundle_txn_cnt;
    ctx->bundle_closed     = 0;
    ctx->bundle_first_tick = fd_tickcount();
    fd_precnf_bundle_init( ctx->bundle );
    if( FD_UNLIKELY( !ctx->bundle_txn_cnt || ctx->bundle_txn_cnt>FD_PRECNF_BUNDLE_TXN_MAX ) ) {
      bundle_drop( ctx, FD_METRICS_ENUM_PRECNF_BUNDLE_DROP_REASON_V_INVALID_IDX );
    }
  }
  if( FD_UNLIKELY( ctx->bundle_closed ) ) return;

  if( FD_UNLIKELY( !fd_precnf_bundle_append( ctx->bundle, fd_txn_m_payload_const( txnm ), txnm->payload_sz, txnm->source_ipv4 ) ) ) {
    bundle_drop( ctx, FD_METRICS_ENUM_PRECNF_BUNDLE_DROP_REASON_V_INVALID_IDX );
    return;
  }
  if( ctx->bundle->txn_cnt==ctx->bundle_txn_cnt ) bundle_complete( ctx );
}

/* before_credit runs on every iteration of the stem loop.  Flushes an
   open batch once its first transaction has waited FD_PRECNF_FLUSH_NS,
   and drives the relayer client (as fd_event_tile does) when its socket
   is ready or its next deadline has passed. */

static void
before_credit( fd_precnf_tile_t *  ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;
  if( FD_UNLIKELY( fd_precnf_batch_txn_cnt( ctx->batch ) &&
                   fd_tickcount()-ctx->batch_first_tick>=ctx->flush_ticks ) ) {
    flush_batch( ctx );
    *charge_busy = 1;
  }
  if( FD_UNLIKELY( fd_precnf_bundle_batch_cnt( ctx->bundle_batch ) &&
                   fd_tickcount()-ctx->bundle_batch_first_tick>=ctx->flush_ticks ) ) {
    flush_bundle_batch( ctx );
    *charge_busy = 1;
  }

  ctx->idle_cnt++;
  if( FD_LIKELY( ctx->idle_cnt<2UL*ctx->in_cnt ) ) return;
  ctx->idle_cnt = 0UL;

  if( FD_UNLIKELY( ctx->bundle_id && !ctx->bundle_closed &&
                   fd_tickcount()-ctx->bundle_first_tick>=ctx->bundle_timeout_ticks ) ) {
    bundle_drop( ctx, FD_METRICS_ENUM_PRECNF_BUNDLE_DROP_REASON_V_PARTIAL_IDX );
  }

  int  fired = fd_fseq_query( ctx->waker_fseq )==1UL;
  long now   = fd_log_wallclock();
  if( FD_UNLIKELY( fired | ( now>=ctx->next_poll_deadline ) ) ) {
    if( FD_LIKELY( fired ) ) fd_fseq_update( ctx->waker_fseq, 0UL );
    int busy = 0;
    fd_precnf_client_poll( ctx->client, now, &busy );
    if( FD_LIKELY( fired ) ) fd_waker_client_rearm( ctx->waker_client_idx );
    *charge_busy |= busy;
    ctx->next_poll_deadline = busy ? 0L : fd_precnf_client_next_deadline( ctx->client, now );
  }
}

/* next_deadline tells stem when this tile must run again even without
   new frags (used when tiles park in efficient mode), in ticks. */

static long
next_deadline( fd_precnf_tile_t * ctx ) {
  long deadline = LONG_MAX;
  if( FD_UNLIKELY( fd_precnf_batch_txn_cnt( ctx->batch ) ) ) deadline = ctx->batch_first_tick + ctx->flush_ticks;
  if( FD_UNLIKELY( fd_precnf_bundle_batch_cnt( ctx->bundle_batch ) ) )
    deadline = fd_long_min( deadline, ctx->bundle_batch_first_tick + ctx->flush_ticks );
  if( FD_LIKELY( ctx->next_poll_deadline!=LONG_MAX ) ) {
    long now_ns = fd_log_wallclock();
    long now_t  = fd_tickcount();
    long dt_ns  = fd_long_max( ctx->next_poll_deadline-now_ns, 0L );
    deadline = fd_long_min( deadline, now_t + (long)( (double)dt_ns*ctx->tick_per_ns ) );
  }
  return deadline;
}

static void
during_frag( fd_precnf_tile_t * ctx,
             ulong              in_idx,
             ulong              seq,
             ulong              sig,
             ulong              chunk,
             ulong              sz,
             ulong              ctl ) {
  (void)seq; (void)sig; (void)ctl;

  fd_precnf_tile_in_t const * in = &ctx->in[ in_idx ];
  if( FD_UNLIKELY( chunk<in->chunk0 || chunk>in->wmark || sz>in->mtu || sz>sizeof(ctx->frag) ) )
    FD_LOG_CRIT(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, in->chunk0, in->wmark ));

  /* Copy now: the producer does not wait for us, so the frag may be
     overwritten at any time after this callback returns. */
  fd_memcpy( ctx->frag, fd_chunk_to_laddr_const( in->mem, chunk ), sz );
  ctx->frag_sz = sz;
}

static void
after_frag( fd_precnf_tile_t *  ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)seq; (void)sig; (void)sz; (void)tsorig; (void)tspub; (void)stem;

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_BUNDLE_UUID ) ) {
    if( FD_UNLIKELY( ctx->frag_sz!=sizeof(fd_bundle_uuid_t) ) ) FD_LOG_CRIT(( "bundle uuid frag size %lu", ctx->frag_sz ));
    fd_bundle_uuid_t const * u = (fd_bundle_uuid_t const *)ctx->frag;
    ctx->uuids[ u->bundle_seq & (FD_PRECNF_UUID_TABLE_CNT-1UL) ] = *u;
    ctx->metrics.bundle_uuid_received++;
    return;
  }

  fd_txn_m_t const * txnm = (fd_txn_m_t const *)ctx->frag;
  if( FD_UNLIKELY( sizeof(fd_txn_m_t)+txnm->payload_sz>ctx->frag_sz ) )
    FD_LOG_CRIT(( "txn payload size %hu exceeds frag size %lu", txnm->payload_sz, ctx->frag_sz ));

  /* 1. BAM transactions that failed verify/dedup are still published by
        FireBAM (with the parsed txn cleared) so pack can report the
        failure.  They are unverified: never forward them.  This must be
        checked before the vote check, which reads the parsed txn. */
  if( FD_UNLIKELY( txnm->source_tpu==FD_TXN_M_TPU_SOURCE_BAM && txnm->bam.preprocess_failed ) ) {
    ctx->metrics.bam_preprocess_failed_skipped++;
    return;
  }

  /* 2. Simple votes are never forwarded. */
  if( FD_UNLIKELY( fd_bam_txn_is_simple_vote( fd_txn_m_txn_t_const( txnm ), fd_txn_m_payload_const( txnm ) ) ) ) {
    ctx->metrics.vote_skipped++;
    return;
  }

  /* 3. Classify.  BAM must be checked first: FireBAM reuses
        block_engine.bundle_id (seq_id+1) for atomic BAM batches, which
        would otherwise look like a Jito bundle. */
  ulong cls;
  switch( txnm->source_tpu ) {
    case FD_TXN_M_TPU_SOURCE_BAM:
      cls = FD_METRICS_ENUM_PRECNF_TXN_CLASS_V_BAM_IDX;
      break;
    case FD_TXN_M_TPU_SOURCE_BUNDLE:
      cls = txnm->block_engine.bundle_id ? FD_METRICS_ENUM_PRECNF_TXN_CLASS_V_JITO_BUNDLE_IDX
                                         : FD_METRICS_ENUM_PRECNF_TXN_CLASS_V_BLOCK_ENGINE_PACKET_IDX;
      break;
    case FD_TXN_M_TPU_SOURCE_QUIC:
      cls = FD_METRICS_ENUM_PRECNF_TXN_CLASS_V_TPU_QUIC_IDX;
      break;
    case FD_TXN_M_TPU_SOURCE_UDP:
      cls = FD_METRICS_ENUM_PRECNF_TXN_CLASS_V_TPU_UDP_IDX;
      break;
    default:
      cls = FD_METRICS_ENUM_PRECNF_TXN_CLASS_V_OTHER_IDX;
      break;
  }
  ctx->metrics.txn_classified[ cls ]++;

  /* Jito bundles are forwarded as whole bundles with their UUID.
     Everything else goes out as a plain packet, which matches the
     reference implementation's handling of TPU, Block Engine packets and
     BAM batches. */
  if( FD_UNLIKELY( cls==FD_METRICS_ENUM_PRECNF_TXN_CLASS_V_JITO_BUNDLE_IDX ) ) {
    bundle_txn( ctx, txnm );
    return;
  }

  /* While the relay stream is not open, drop instead of queueing: the
     queue is cleared when the stream (re)opens anyway. */
  if( FD_UNLIKELY( !fd_precnf_client_streaming( ctx->client ) ) ) {
    ctx->metrics.txn_dropped_not_streaming++;
    return;
  }
  queue_txn( ctx, txnm );
}

static void
during_housekeeping( fd_precnf_tile_t * ctx ) {
  /* set-identity waits for every tile that uses the identity keyswitch
     to acknowledge the switch.  Reconnect and re-authenticate as the new
     identity (the relayer allowlists by pubkey). */
  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    fd_memcpy( ctx->identity_pubkey, ctx->keyswitch->bytes, 32UL );
    fd_precnf_client_set_identity( ctx->client, ctx->identity_pubkey );
    ctx->next_poll_deadline = 0L;
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_precnf_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_precnf_tile_t ), sizeof( fd_precnf_tile_t ) );
  fd_memset( ctx, 0, sizeof( fd_precnf_tile_t ) );

  if( FD_UNLIKELY( !strcmp( tile->precnf.identity_key_path, "" ) ) ) FD_LOG_ERR(( "identity_key_path not set" ));
  uchar const * identity_key = fd_keyload_load( tile->precnf.identity_key_path, /* pubkey only: */ 1 );
  fd_memcpy( ctx->identity_pubkey, identity_key, 32UL );

  FD_TEST( fd_rng_secure( &ctx->seed, 8UL ) );

  /* DNS needs these files after the sandbox is entered. */
  if( FD_UNLIKELY( !fd_netdb_open_fds( ctx->netdb_fds ) ) ) FD_LOG_ERR(( "fd_netdb_open_fds failed" ));

  fd_url_t url[ 1UL ];
  ushort   port;
  _Bool    is_ssl = 0;
  if( FD_UNLIKELY( fd_url_parse_endpoint( url, tile->precnf.url, strlen( tile->precnf.url ), &port, &is_ssl, "[tiles.preconf.url]" ) ) ) {
    FD_LOG_ERR(( "Could not parse [tiles.preconf.url]" ));
  }
  ctx->use_tls = is_ssl;
  if( ctx->use_tls ) {
    /* Load system CA certificates while the tile can still open files. */
    long ca_cnt = fd_x509_ca_store_load_system( ctx->ca_store );
    if( FD_UNLIKELY( ca_cnt<0L ) ) FD_LOG_ERR(( "No CA certificate bundle found, cannot verify the relayer's certificate" ));
  }
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_precnf_tile_t * ctx    = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_precnf_tile_t ), sizeof( fd_precnf_tile_t )                  );
  void *             _circq = FD_SCRATCH_ALLOC_APPEND( l, fd_circq_align(),            fd_circq_footprint( FD_PRECNF_CIRCQ_SZ ) );
  void *             _client = FD_SCRATCH_ALLOC_APPEND( l, fd_precnf_client_align(),   fd_precnf_client_footprint( FD_PRECNF_GRPC_BUF_MAX ) );

  ctx->circq = fd_circq_join( fd_circq_new( _circq, FD_PRECNF_CIRCQ_SZ ) );
  FD_TEST( ctx->circq );
  fd_precnf_batch_init( ctx->batch );
  ctx->batch_first_tick = 0L;
  ctx->flush_ticks      = fd_long_max( 1L, (long)( (double)FD_PRECNF_FLUSH_NS * fd_tempo_tick_per_ns( NULL ) ) );
  fd_precnf_bundle_init( ctx->bundle );
  fd_precnf_bundle_batch_init( ctx->bundle_batch );
  ctx->bundle_id            = 0UL;
  ctx->bundle_closed        = 1;
  ctx->bundle_timeout_ticks = (long)( (double)FD_PRECNF_BUNDLE_TIMEOUT_NS * fd_tempo_tick_per_ns( NULL ) );

  ulong sign_in_idx  = fd_topo_find_tile_in_link ( topo, tile, "sign_precnf", tile->kind_id );
  ulong sign_out_idx = fd_topo_find_tile_out_link( topo, tile, "precnf_sign", tile->kind_id );
  FD_TEST( sign_in_idx!=ULONG_MAX && sign_out_idx!=ULONG_MAX );
  fd_topo_link_t const * sign_in  = &topo->links[ tile->in_link_id [ sign_in_idx  ] ];
  fd_topo_link_t const * sign_out = &topo->links[ tile->out_link_id[ sign_out_idx ] ];

  fd_sleep_t * sleep = NULL;
  if( FD_UNLIKELY( topo->sleep_obj_id!=ULONG_MAX ) ) {
    sleep = fd_sleep_join( fd_topo_obj_laddr( topo, topo->sleep_obj_id ) );
    FD_TEST( sleep );
  }

  if( FD_UNLIKELY( !fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
          sign_out->mcache,
          sign_out->dcache,
          sign_in->mcache,
          sign_in->dcache,
          sign_out->mtu,
          sign_in->mtu,
          sleep,
          sign_out->id,
          fd_topo_find_link_consumer( topo, sign_out ) ) ) ) ) {
    FD_LOG_ERR(( "failed to construct keyguard" ));
  }

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  FD_TEST( fd_rng_join( fd_rng_new( ctx->rng, 0U, ctx->seed ) ) );

  ctx->waker_client_idx = tile->waker_client_idx;
  FD_TEST( ctx->waker_client_idx!=ULONG_MAX );
  ctx->waker_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, tile->waker_fseq_obj_id ) );
  FD_TEST( ctx->waker_fseq );

  ctx->client = fd_precnf_client_join( fd_precnf_client_new( _client,
                                                             ctx->keyguard_client,
                                                             ctx->rng,
                                                             ctx->circq,
                                                             FD_WAKER_INNER_FD( ctx->waker_client_idx ),
                                                             tile->precnf.url,
                                                             ctx->identity_pubkey,
                                                             FD_PRECNF_GRPC_BUF_MAX,
                                                             ctx->use_tls,
                                                             ctx->use_tls ? ctx->ca_store : NULL ) );
  FD_TEST( ctx->client );
  ctx->next_poll_deadline = 0L;
  ctx->idle_cnt           = 0UL;
  ctx->tick_per_ns        = fd_tempo_tick_per_ns( NULL );

  FD_TEST( tile->in_cnt<=sizeof(ctx->in_kind)/sizeof(ctx->in_kind[0]) );
  ulong polled_in_idx = 0UL;
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    if( FD_UNLIKELY( !tile->in_link_poll[ i ] ) ) continue; /* sign_precnf is read by the keyguard client */

    fd_topo_link_t const * link      = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t const * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    /* dedup_resolv in Firedancer, dedup_resolh in Frankendancer. */
    if(      FD_LIKELY( !strcmp( link->name, "dedup_resolv"  ) ||
                        !strcmp( link->name, "dedup_resolh"  ) ) ) ctx->in_kind[ polled_in_idx ] = IN_KIND_DEDUP;
    else if( FD_LIKELY( !strcmp( link->name, "bundle_precnf" ) ) ) ctx->in_kind[ polled_in_idx ] = IN_KIND_BUNDLE_UUID;
    else FD_LOG_ERR(( "precnf tile has unexpected input link %lu %s", i, link->name ));

    ctx->in[ polled_in_idx ].mem    = link_wksp->wksp;
    ctx->in[ polled_in_idx ].mtu    = link->mtu;
    ctx->in[ polled_in_idx ].chunk0 = fd_dcache_compact_chunk0( link_wksp->wksp, link->dcache );
    ctx->in[ polled_in_idx ].wmark  = fd_dcache_compact_wmark ( link_wksp->wksp, link->dcache, link->mtu );
    polled_in_idx++;
  }
  ctx->in_cnt = polled_in_idx;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  fd_precnf_tile_t const * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  populate_sock_filter_policy_fd_precnf_tile(
      out_cnt, out,
      (uint)fd_log_private_logfile_fd(),
      (uint)ctx->netdb_fds->etc_hosts,
      (uint)ctx->netdb_fds->etc_resolv_conf,
      (uint)FD_WAKER_INNER_FD( tile->waker_client_idx ),
      (uint)FD_WAKER_OUTER_FD );
  return sock_filter_policy_fd_precnf_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_precnf_tile_t const * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  if( FD_UNLIKELY( out_fds_cnt<6UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  if( FD_LIKELY( ctx->netdb_fds->etc_hosts>=0 ) )
    out_fds[ out_cnt++ ] = ctx->netdb_fds->etc_hosts;
  out_fds[ out_cnt++ ] = ctx->netdb_fds->etc_resolv_conf;
  out_fds[ out_cnt++ ] = FD_WAKER_OUTER_FD;                           /* waker outer epoll fd (rearm) */
  out_fds[ out_cnt++ ] = FD_WAKER_INNER_FD( tile->waker_client_idx ); /* waker inner epoll fd */
  return out_cnt;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  ((long)10e6) /* 10ms */

#define STEM_CALLBACK_CONTEXT_TYPE  fd_precnf_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_precnf_tile_t)

#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_NEXT_DEADLINE       next_deadline
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping

#include "../stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_precnf = {
  .name                     = "precnf",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
  .rlimit_file_cnt          = 5UL, /* stderr, logfile, /etc/hosts, /etc/resolv.conf, socket to the relayer */
  .keep_host_networking     = 1,
  .allow_connect            = 1,
};

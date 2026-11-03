#include "fd_precnf_encode.h"
#include "../../third_party/nanopb/pb_encode.h"

/* Formats a network byte order IPv4 address as dotted decimal into out
   (NUL-terminated, at most 15 characters). */

static void
fmt_ip4( char out[ 16 ],
         uint ipv4 ) {
  uchar const * b = (uchar const *)&ipv4;
  char * p = out;
  for( ulong i=0UL; i<4UL; i++ ) {
    uint v = b[ i ];
    if( v>=100U ) { *p++ = (char)( '0'+v/100U ); v %= 100U; *p++ = (char)( '0'+v/10U ); v %= 10U; }
    else if( v>=10U ) { *p++ = (char)( '0'+v/10U ); v %= 10U; }
    *p++ = (char)( '0'+v );
    if( i<3UL ) *p++ = '.';
  }
  *p = '\0';
}

/* fill_packet sets pkt to a transaction with the reference
   implementation's metadata.  Returns 0 if the payload is too large. */

static int
fill_packet( packet_Packet * pkt,
             uchar const *   payload,
             ulong           payload_sz,
             uint            ipv4 ) {
  if( FD_UNLIKELY( payload_sz>sizeof(pkt->data.bytes) ) ) return 0;

  pkt->data.size = (pb_size_t)payload_sz;
  fd_memcpy( pkt->data.bytes, payload, payload_sz );

  pkt->has_meta          = true;
  pkt->meta.size         = payload_sz;
  pkt->meta.port         = 0U;
  pkt->meta.sender_stake = 0UL;
  pkt->meta.has_flags    = true; /* present but all false, as in the reference */
  pkt->meta.flags        = (packet_PacketFlags)packet_PacketFlags_init_zero;
  if( ipv4 ) fmt_ip4( pkt->meta.addr, ipv4 );
  else       pkt->meta.addr[ 0 ] = '\0';
  return 1;
}

static bool
encode_packet_array( pb_ostream_t *        stream,
                     pb_field_t const *    field,
                     packet_Packet const * pkts,
                     ulong                 cnt ) {
  for( ulong i=0UL; i<cnt; i++ ) {
    if( FD_UNLIKELY( !pb_encode_tag_for_field( stream, field ) ) ) return false;
    if( FD_UNLIKELY( !pb_encode_submessage( stream, packet_Packet_fields, &pkts[ i ] ) ) ) return false;
  }
  return true;
}

/* Encode callback for the repeated PacketBatch.packets field. */

static bool
encode_packets( pb_ostream_t *     stream,
                pb_field_t const * field,
                void * const *     arg ) {
  fd_precnf_batch_t const * batch = *arg;
  return encode_packet_array( stream, field, batch->pkts, batch->txn_cnt );
}

/* Encode callback for the repeated Bundle.packets field. */

static bool
encode_bundle_packets( pb_ostream_t *     stream,
                       pb_field_t const * field,
                       void * const *     arg ) {
  fd_precnf_bundle_t const * bundle = *arg;
  return encode_packet_array( stream, field, bundle->pkts, bundle->txn_cnt );
}

static void
set_ts( shared_Header * header,
        long            wallclock_ns ) {
  header->has_ts     = true;
  header->ts.seconds = wallclock_ns/1000000000L;
  header->ts.nanos   = (int)( wallclock_ns%1000000000L );
}

/* Encode callback for the repeated ExpiringBundleBatch.bundles field.
   arg points to a bundle_ctx_t. */

typedef struct {
  fd_precnf_bundle_batch_t const * batch;
  long                             wallclock_ns;
} bundle_ctx_t;

static bool
encode_bundles( pb_ostream_t *     stream,
                pb_field_t const * field,
                void * const *     arg ) {
  bundle_ctx_t const * bctx = *arg;
  for( ulong i=0UL; i<bctx->batch->bundle_cnt; i++ ) {
    fd_precnf_bundle_t const * b = &bctx->batch->bundles[ i ];
    bundle_BundleUuid msg = bundle_BundleUuid_init_zero;
    msg.has_bundle        = true;
    msg.bundle.has_header = true;
    set_ts( &msg.bundle.header, bctx->wallclock_ns );
    msg.bundle.packets.funcs.encode = encode_bundle_packets;
    msg.bundle.packets.arg          = (void *)b;
    msg.uuid.size = (pb_size_t)b->uuid_sz;
    fd_memcpy( msg.uuid.bytes, b->uuid, b->uuid_sz );
    if( FD_UNLIKELY( !pb_encode_tag_for_field( stream, field ) ) ) return false;
    if( FD_UNLIKELY( !pb_encode_submessage( stream, bundle_BundleUuid_fields, &msg ) ) ) return false;
  }
  return true;
}

static void
fill_relay_update( astralane_relayer_RelayUpdate * msg,
                   fd_precnf_batch_t const *       batch,
                   long                            wallclock_ns ) {
  *msg = (astralane_relayer_RelayUpdate)astralane_relayer_RelayUpdate_init_zero;
  msg->which_msg = astralane_relayer_RelayUpdate_batches_tag;
  astralane_relayer_ExpiringPacketBatch * epb = &msg->msg.batches;
  epb->has_header           = true;
  set_ts( &epb->header, wallclock_ns );
  epb->has_batch            = true;
  epb->batch.packets.funcs.encode = encode_packets;
  epb->batch.packets.arg    = (void *)batch;
}

ulong
fd_precnf_encode_heartbeat( uchar out[ FD_PRECNF_HEARTBEAT_ENC_MAX ],
                            ulong count ) {
  astralane_relayer_RelayUpdate msg = astralane_relayer_RelayUpdate_init_zero;
  msg.which_msg           = astralane_relayer_RelayUpdate_heartbeat_tag;
  msg.msg.heartbeat.count = count;
  pb_ostream_t stream = pb_ostream_from_buffer( out, FD_PRECNF_HEARTBEAT_ENC_MAX );
  FD_TEST( pb_encode( &stream, astralane_relayer_RelayUpdate_fields, &msg ) );
  return stream.bytes_written;
}

fd_precnf_batch_t *
fd_precnf_batch_init( fd_precnf_batch_t * batch ) {
  batch->txn_cnt = 0UL;
  return batch;
}

int
fd_precnf_batch_append( fd_precnf_batch_t * batch,
                        uchar const *       payload,
                        ulong               payload_sz,
                        uint                ipv4 ) {
  if( FD_UNLIKELY( batch->txn_cnt>=FD_PRECNF_BATCH_TXN_MAX ) ) return 0;
  if( FD_UNLIKELY( !fill_packet( &batch->pkts[ batch->txn_cnt ], payload, payload_sz, ipv4 ) ) ) return 0;
  batch->txn_cnt++;
  return 1;
}

ulong
fd_precnf_batch_encoded_sz( fd_precnf_batch_t const * batch,
                            long                      wallclock_ns ) {
  FD_TEST( batch->txn_cnt );
  astralane_relayer_RelayUpdate msg;
  fill_relay_update( &msg, batch, wallclock_ns );
  size_t sz;
  FD_TEST( pb_get_encoded_size( &sz, astralane_relayer_RelayUpdate_fields, &msg ) );
  return (ulong)sz;
}

ulong
fd_precnf_batch_encode( fd_precnf_batch_t const * batch,
                        long                      wallclock_ns,
                        uchar *                   out,
                        ulong                     out_sz ) {
  FD_TEST( batch->txn_cnt );
  astralane_relayer_RelayUpdate msg;
  fill_relay_update( &msg, batch, wallclock_ns );
  pb_ostream_t stream = pb_ostream_from_buffer( out, out_sz );
  if( FD_UNLIKELY( !pb_encode( &stream, astralane_relayer_RelayUpdate_fields, &msg ) ) ) return 0UL;
  return stream.bytes_written;
}

fd_precnf_bundle_t *
fd_precnf_bundle_init( fd_precnf_bundle_t * bundle ) {
  bundle->txn_cnt = 0UL;
  bundle->uuid_sz = 0UL;
  return bundle;
}

int
fd_precnf_bundle_append( fd_precnf_bundle_t * bundle,
                         uchar const *        payload,
                         ulong                payload_sz,
                         uint                 ipv4 ) {
  if( FD_UNLIKELY( bundle->txn_cnt>=FD_PRECNF_BUNDLE_TXN_MAX ) ) return 0;
  if( FD_UNLIKELY( !fill_packet( &bundle->pkts[ bundle->txn_cnt ], payload, payload_sz, ipv4 ) ) ) return 0;
  bundle->txn_cnt++;
  return 1;
}

int
fd_precnf_bundle_set_uuid( fd_precnf_bundle_t * bundle,
                           uchar const *        uuid,
                           ulong                uuid_sz ) {
  if( FD_UNLIKELY( uuid_sz>FD_PRECNF_BUNDLE_UUID_MAX ) ) return 0;
  fd_memcpy( bundle->uuid, uuid, uuid_sz );
  bundle->uuid_sz = uuid_sz;
  return 1;
}

fd_precnf_bundle_batch_t *
fd_precnf_bundle_batch_init( fd_precnf_bundle_batch_t * batch ) {
  batch->bundle_cnt = 0UL;
  batch->txn_cnt    = 0UL;
  return batch;
}

int
fd_precnf_bundle_batch_append( fd_precnf_bundle_batch_t * batch,
                               fd_precnf_bundle_t const * bundle ) {
  FD_TEST( bundle->txn_cnt );
  if( FD_UNLIKELY( batch->bundle_cnt>=FD_PRECNF_BUNDLE_BATCH_MAX ) ) return 0;
  fd_precnf_bundle_t * dst = &batch->bundles[ batch->bundle_cnt ];
  dst->txn_cnt = bundle->txn_cnt;
  dst->uuid_sz = bundle->uuid_sz;
  fd_memcpy( dst->uuid, bundle->uuid, bundle->uuid_sz );
  fd_memcpy( dst->pkts, bundle->pkts, bundle->txn_cnt*sizeof(packet_Packet) );
  batch->bundle_cnt++;
  batch->txn_cnt += bundle->txn_cnt;
  return 1;
}

static void
fill_bundle_update( astralane_relayer_RelayUpdate * msg,
                    bundle_ctx_t *                  bctx ) {
  *msg = (astralane_relayer_RelayUpdate)astralane_relayer_RelayUpdate_init_zero;
  msg->which_msg = astralane_relayer_RelayUpdate_bundles_tag;
  astralane_relayer_ExpiringBundleBatch * ebb = &msg->msg.bundles;
  ebb->has_header = true;
  set_ts( &ebb->header, bctx->wallclock_ns );
  ebb->bundles.funcs.encode = encode_bundles;
  ebb->bundles.arg          = bctx;
}

ulong
fd_precnf_bundle_batch_encoded_sz( fd_precnf_bundle_batch_t const * batch,
                                   long                             wallclock_ns ) {
  FD_TEST( batch->bundle_cnt );
  bundle_ctx_t bctx = { .batch = batch, .wallclock_ns = wallclock_ns };
  astralane_relayer_RelayUpdate msg;
  fill_bundle_update( &msg, &bctx );
  size_t sz;
  FD_TEST( pb_get_encoded_size( &sz, astralane_relayer_RelayUpdate_fields, &msg ) );
  return (ulong)sz;
}

ulong
fd_precnf_bundle_batch_encode( fd_precnf_bundle_batch_t const * batch,
                               long                             wallclock_ns,
                               uchar *                          out,
                               ulong                            out_sz ) {
  FD_TEST( batch->bundle_cnt );
  bundle_ctx_t bctx = { .batch = batch, .wallclock_ns = wallclock_ns };
  astralane_relayer_RelayUpdate msg;
  fill_bundle_update( &msg, &bctx );
  pb_ostream_t stream = pb_ostream_from_buffer( out, out_sz );
  if( FD_UNLIKELY( !pb_encode( &stream, astralane_relayer_RelayUpdate_fields, &msg ) ) ) return 0UL;
  return stream.bytes_written;
}

#ifndef HEADER_fd_src_disco_preconf_fd_precnf_encode_h
#define HEADER_fd_src_disco_preconf_fd_precnf_encode_h

/* fd_precnf_encode.h serializes the messages the precnf tile sends on
   the astralane_relayer.AstralaneRelayer/StartRelayStream stream, using
   the nanopb tables generated from proto/astralane_relayer.proto:

     RelayUpdate { heartbeat (2): shared.Heartbeat { count (1) } }
     RelayUpdate { bundles   (3): ExpiringBundleBatch {
                     header  (1): shared.Header { ts (1) }
                     bundles (2, repeated): bundle.BundleUuid {
                                   bundle (1): bundle.Bundle {
                                                 header  (2): shared.Header { ts (1) }
                                                 packets (3, repeated): packet.Packet }
                                   uuid   (2) }
                     expiry_ms (3) } }
     RelayUpdate { batches   (1): ExpiringPacketBatch {
                     header (1): shared.Header { ts (1): Timestamp }
                     batch  (2): packet.PacketBatch { packets (1, repeated): packet.Packet {
                                   data (1),
                                   meta (2): packet.Meta { size (1), addr (2), port (3),
                                                           flags (4): PacketFlags {}, sender_stake (5) } } }
                     expiry_ms (3) } }

   nanopb produces canonical encodings (minimal varints, proto3 default
   values omitted), so the output is byte-identical to what jito-agave
   (prost) produces for the same field values.

   Values the validator does not know are sent as defaults, as in the
   reference implementation: port 0, sender_stake 0, all flags false
   (but present, so encoded as an empty submessage), expiry_ms 0.  addr
   is the sender's dotted IPv4 address, omitted when unknown (ipv4==0,
   e.g. BAM). */

#include "../../util/fd_util_base.h"
#include "../../ballet/fd_ballet_base.h" /* FD_TPU_MTU */
#include "proto/astralane_relayer.pb.h"

/* FD_PRECNF_BATCH_TXN_MAX is the max number of transactions per
   RelayUpdate batch. */

#define FD_PRECNF_BATCH_TXN_MAX (64UL)

/* FD_PRECNF_PACKET_ENC_MAX is the worst-case encoded size of one
   PacketBatch.packets entry carrying a FD_TPU_MTU byte transaction. */

#define FD_PRECNF_PACKET_ENC_MAX (FD_TPU_MTU+64UL)

/* FD_PRECNF_BATCH_ENC_MAX bounds the encoded size of a full batch of
   FD_PRECNF_BATCH_TXN_MAX max-size transactions (64 bytes of headers). */

#define FD_PRECNF_BATCH_ENC_MAX (64UL + FD_PRECNF_BATCH_TXN_MAX*FD_PRECNF_PACKET_ENC_MAX)

/* FD_PRECNF_BUNDLE_TXN_MAX is the max number of transactions in a
   bundle (as in the block engine and fd_bundle_client).
   FD_PRECNF_BUNDLE_UUID_MAX is the max uuid length.
   FD_PRECNF_BUNDLE_BATCH_MAX is the max number of bundles per
   RelayUpdate. */

#define FD_PRECNF_BUNDLE_TXN_MAX   (5UL)
#define FD_PRECNF_BUNDLE_UUID_MAX  (128UL)
#define FD_PRECNF_BUNDLE_BATCH_MAX (16UL)

/* FD_PRECNF_BUNDLE_BATCH_ENC_MAX bounds the encoded size of a full
   bundle batch of max-size bundles (256 bytes of headers and uuid per
   bundle). */

#define FD_PRECNF_BUNDLE_BATCH_ENC_MAX \
  (64UL + FD_PRECNF_BUNDLE_BATCH_MAX*( 256UL + FD_PRECNF_BUNDLE_TXN_MAX*FD_PRECNF_PACKET_ENC_MAX ))

/* FD_PRECNF_HEARTBEAT_ENC_MAX is the max encoded size of a heartbeat. */

#define FD_PRECNF_HEARTBEAT_ENC_MAX (16UL)

/* fd_precnf_batch_t holds the transactions of one RelayUpdate batch
   until it is encoded.  Each transaction is copied into a nanopb Packet
   on append. */

struct fd_precnf_batch {
  ulong         txn_cnt;
  packet_Packet pkts[ FD_PRECNF_BATCH_TXN_MAX ];
};

typedef struct fd_precnf_batch fd_precnf_batch_t;

/* fd_precnf_bundle_t holds one Jito bundle: its transactions in order
   and its uuid. */

struct fd_precnf_bundle {
  ulong         txn_cnt;
  ulong         uuid_sz;
  uchar         uuid[ FD_PRECNF_BUNDLE_UUID_MAX ];
  packet_Packet pkts[ FD_PRECNF_BUNDLE_TXN_MAX ];
};

typedef struct fd_precnf_bundle fd_precnf_bundle_t;

/* fd_precnf_bundle_batch_t holds the bundles of one RelayUpdate. */

struct fd_precnf_bundle_batch {
  ulong              bundle_cnt;
  ulong              txn_cnt;   /* sum over bundles */
  fd_precnf_bundle_t bundles[ FD_PRECNF_BUNDLE_BATCH_MAX ];
};

typedef struct fd_precnf_bundle_batch fd_precnf_bundle_batch_t;

FD_PROTOTYPES_BEGIN

/* fd_precnf_encode_heartbeat writes RelayUpdate{heartbeat{count}} to
   out (at least FD_PRECNF_HEARTBEAT_ENC_MAX bytes) and returns the
   encoded size. */

ulong
fd_precnf_encode_heartbeat( uchar out[ FD_PRECNF_HEARTBEAT_ENC_MAX ],
                            ulong count );

/* fd_precnf_batch_init empties a batch.  Returns batch. */

fd_precnf_batch_t *
fd_precnf_batch_init( fd_precnf_batch_t * batch );

/* fd_precnf_batch_append adds one transaction.  ipv4 is the sender's
   address in network byte order (as in fd_txn_m_t.source_ipv4), 0 if
   unknown.  Returns 1 on success, 0 if the batch is full or the payload
   is larger than FD_TPU_MTU (nothing is added). */

int
fd_precnf_batch_append( fd_precnf_batch_t * batch,
                        uchar const *       payload,
                        ulong               payload_sz,
                        uint                ipv4 );

/* fd_precnf_batch_encoded_sz returns the exact encoded size of the
   batch as a RelayUpdate.  The batch must hold at least one
   transaction.  The size does not depend on the timestamp's value
   beyond its varint lengths, so pass the same wallclock_ns to
   fd_precnf_batch_encode. */

ulong
fd_precnf_batch_encoded_sz( fd_precnf_batch_t const * batch,
                            long                      wallclock_ns );

/* fd_precnf_batch_encode writes the batch as a RelayUpdate with
   header.ts set to wallclock_ns (UNIX nanoseconds).  Returns the
   encoded size, or 0 if out_sz is too small. */

ulong
fd_precnf_batch_encode( fd_precnf_batch_t const * batch,
                        long                      wallclock_ns,
                        uchar *                   out,
                        ulong                     out_sz );

static inline ulong
fd_precnf_batch_txn_cnt( fd_precnf_batch_t const * batch ) {
  return batch->txn_cnt;
}

/* fd_precnf_bundle_init empties a bundle.  Returns bundle. */

fd_precnf_bundle_t *
fd_precnf_bundle_init( fd_precnf_bundle_t * bundle );

/* fd_precnf_bundle_append adds the next transaction of a bundle (same
   arguments as fd_precnf_batch_append).  Returns 1 on success, 0 if the
   bundle is full or the payload is too large. */

int
fd_precnf_bundle_append( fd_precnf_bundle_t * bundle,
                         uchar const *        payload,
                         ulong                payload_sz,
                         uint                 ipv4 );

/* fd_precnf_bundle_set_uuid sets the bundle's uuid.  Returns 1 on
   success, 0 if uuid_sz>FD_PRECNF_BUNDLE_UUID_MAX. */

int
fd_precnf_bundle_set_uuid( fd_precnf_bundle_t * bundle,
                           uchar const *        uuid,
                           ulong                uuid_sz );

/* fd_precnf_bundle_batch_init empties a bundle batch.  Returns batch. */

fd_precnf_bundle_batch_t *
fd_precnf_bundle_batch_init( fd_precnf_bundle_batch_t * batch );

/* fd_precnf_bundle_batch_append copies a complete bundle (at least one
   transaction) into the batch.  Returns 1 on success, 0 if the batch is
   full. */

int
fd_precnf_bundle_batch_append( fd_precnf_bundle_batch_t * batch,
                               fd_precnf_bundle_t const * bundle );

static inline ulong
fd_precnf_bundle_batch_cnt( fd_precnf_bundle_batch_t const * batch ) {
  return batch->bundle_cnt;
}

/* fd_precnf_bundle_batch_encoded_sz and fd_precnf_bundle_batch_encode
   are like the fd_precnf_batch versions, for a RelayUpdate{bundles}.
   Every header.ts (of the batch and of each bundle) is wallclock_ns. */

ulong
fd_precnf_bundle_batch_encoded_sz( fd_precnf_bundle_batch_t const * batch,
                                   long                             wallclock_ns );

ulong
fd_precnf_bundle_batch_encode( fd_precnf_bundle_batch_t const * batch,
                               long                             wallclock_ns,
                               uchar *                          out,
                               ulong                            out_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_preconf_fd_precnf_encode_h */

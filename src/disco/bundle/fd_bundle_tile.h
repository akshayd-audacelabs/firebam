#ifndef HEADER_fd_src_disco_bundle_fd_bundle_tile_h
#define HEADER_fd_src_disco_bundle_fd_bundle_tile_h

/* fd_bundle_tile.h provides a bundle client tile.

   - Uses HTTP/2 over TCP sockets, with TLS (https) or plaintext (http)
   - Uses fd_tls for handshake and record layers
   - Uses Firedancer's fd_h2 and fd_grpc for HTTP/2 and gRPC logic
   - Cooperatively scheduled
   - Disconnects and sleeps while the next leader slot is far away */

#include "../topo/fd_topo.h"
#include "../../waltz/http/fd_url.h"

struct fd_bundle_tile;
typedef struct fd_bundle_tile fd_bundle_tile_t;

#define FD_BUNDLE_STATE_DISCONNECTED (0)
#define FD_BUNDLE_STATE_CONNECTING   (1)
#define FD_BUNDLE_STATE_CONNECTED    (2)
#define FD_BUNDLE_STATE_SLEEPING     (3)

struct fd_bundle_block_engine_update {
  char name[ 16 ];
  char url[ FD_URL_MAX ];
  char ip_cstr[ 40 ]; /* IPv4 or IPv6 cstr */
};
typedef struct fd_bundle_block_engine_update fd_bundle_block_engine_update_t;

/* fd_bundle_uuid_t is published on the optional bundle_precnf link (to
   the pre-confirmation tile) for each bundle, right before the bundle's
   transactions are published to verify.  bundle_seq equals
   fd_txn_m_t.block_engine.bundle_id of those transactions.  uuid is the
   block engine's BundleUuid.uuid. */

#define FD_BUNDLE_UUID_MAX (128UL)

struct fd_bundle_uuid {
  ulong bundle_seq;
  ulong txn_cnt;
  ulong uuid_sz;
  uchar uuid[ FD_BUNDLE_UUID_MAX ];
};
typedef struct fd_bundle_uuid fd_bundle_uuid_t;

FD_PROTOTYPES_BEGIN

extern fd_topo_run_tile_t fd_tile_bundle;

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_bundle_fd_bundle_tile_h */

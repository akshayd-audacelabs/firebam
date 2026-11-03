#ifndef HEADER_fd_src_disco_preconf_fd_precnf_auth_h
#define HEADER_fd_src_disco_preconf_fd_precnf_auth_h

/* fd_precnf_auth.h acquires and refreshes the access token used on the
   pre-confirmation relayer's StartRelayStream request.  It speaks Jito's
   auth.AuthService (the same service and challenge format the bundle
   tile uses), authenticating with role RELAYER:

   - Request a challenge for our pubkey (GenerateAuthChallenge)
   - Sign "<base58 pubkey>-<challenge>" via the sign tile and exchange
     it for an access token and a refresh token (GenerateAuthTokens)
   - While connected, when the access token has less than
     FD_PRECNF_AUTH_REFRESH_MARGIN_NS left, get a new one with the
     refresh token (RefreshAccessToken).  When the refresh token itself
     is about to expire, run the full challenge again.

   The authorization header is only sent when a stream is opened, so a
   refreshed access token is used by the next StartRelayStream (after a
   reconnect), not by the stream that is already open.  This matches the
   reference implementation. */

#include "../../waltz/grpc/fd_grpc_client.h"
#include "../keyguard/fd_keyguard_client.h"

/* Request contexts (echoed in fd_grpc_client callbacks). */

#define FD_PRECNF_REQ_AUTH_CHALLENGE  (1UL)
#define FD_PRECNF_REQ_AUTH_TOKENS     (2UL)
#define FD_PRECNF_REQ_AUTH_REFRESH    (3UL)
#define FD_PRECNF_REQ_RELAY_STREAM    (4UL)

#define FD_PRECNF_AUTH_STATE_REQ_CHALLENGE  (0)
#define FD_PRECNF_AUTH_STATE_WAIT_CHALLENGE (1)
#define FD_PRECNF_AUTH_STATE_REQ_TOKENS     (2)
#define FD_PRECNF_AUTH_STATE_WAIT_TOKENS    (3)
#define FD_PRECNF_AUTH_STATE_DONE           (4) /* access token usable */
#define FD_PRECNF_AUTH_STATE_REQ_REFRESH    (5) /* token usable, refresh due */
#define FD_PRECNF_AUTH_STATE_WAIT_REFRESH   (6) /* token usable, refresh in flight */

/* Refresh tokens that expire within this margin (5 minutes, as in the
   reference implementation). */

#define FD_PRECNF_AUTH_REFRESH_MARGIN_NS (300L*(long)1e9)

/* Timeout for each auth request. */

#define FD_PRECNF_AUTH_REQUEST_TIMEOUT_NS (5L*(long)1e9)

struct fd_precnf_auther {
  int   state;
  uint  needs_poll : 1;
  uchar pubkey[ 32 ];

  char   challenge[ 9 ];

  char   access_token[ 1024 ];
  ushort access_token_sz;
  long   access_expiry_ns;  /* UNIX ns */

  char   refresh_token[ 1024 ];
  ushort refresh_token_sz;
  long   refresh_expiry_ns; /* UNIX ns */

  ulong  refresh_cnt;       /* successful RefreshAccessToken calls */
  ulong  auth_cnt;          /* successful full challenge/response flows */
  ulong  fail_cnt;          /* failed or rejected auth requests */
};

typedef struct fd_precnf_auther fd_precnf_auther_t;

FD_PROTOTYPES_BEGIN

fd_precnf_auther_t *
fd_precnf_auther_init( fd_precnf_auther_t * auther,
                       uchar const          pubkey[ 32 ] );

/* fd_precnf_auther_reset forgets all tokens and restarts with a full
   challenge.  Call on connect, on an auth failure and when the identity
   changes (after updating the pubkey). */

void
fd_precnf_auther_reset( fd_precnf_auther_t * auther );

void
fd_precnf_auther_set_pubkey( fd_precnf_auther_t * auther,
                             uchar const          pubkey[ 32 ] );

/* fd_precnf_auther_has_token returns 1 if an access token is available
   for opening the relay stream. */

static inline int
fd_precnf_auther_has_token( fd_precnf_auther_t const * auther ) {
  return auther->state>=FD_PRECNF_AUTH_STATE_DONE;
}

/* fd_precnf_auther_check_expiry schedules a refresh (or a full re-auth)
   if a token is close to expiring.  Cheap; call on every poll while
   connected.  now is UNIX ns. */

void
fd_precnf_auther_check_expiry( fd_precnf_auther_t * auther,
                               long                 now );

/* fd_precnf_auther_poll sends the next auth request if one is due and
   the gRPC client can start a request.  Should be called whenever
   auther->needs_poll is set.  Signing goes through the keyguard client
   (spins until the sign tile replies). */

void
fd_precnf_auther_poll( fd_precnf_auther_t *   auther,
                       fd_grpc_client_t *     client,
                       fd_keyguard_client_t * keyguard,
                       long                   now );

/* Response handlers, called from the gRPC rx callbacks for the auth
   request contexts.  now is UNIX ns. */

void
fd_precnf_auther_handle_resp( fd_precnf_auther_t * auther,
                              ulong                request_ctx,
                              void const *         data,
                              ulong                data_sz,
                              long                 now );

void
fd_precnf_auther_handle_request_fail( fd_precnf_auther_t * auther,
                                      ulong                request_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_preconf_fd_precnf_auth_h */

#include "fd_precnf_auth.h"
#include "../bundle/proto/auth.pb.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../third_party/nanopb/pb_decode.h"
#include "../keyguard/fd_keyguard.h"

/* Adapted from src/disco/bundle/fd_bundle_auth.c: same service and
   challenge format, but authenticates as RELAYER and keeps the refresh
   token so the access token can be refreshed. */

fd_precnf_auther_t *
fd_precnf_auther_init( fd_precnf_auther_t * auther,
                       uchar const          pubkey[ 32 ] ) {
  memset( auther, 0, sizeof(fd_precnf_auther_t) );
  fd_memcpy( auther->pubkey, pubkey, 32UL );
  fd_precnf_auther_reset( auther );
  return auther;
}

void
fd_precnf_auther_reset( fd_precnf_auther_t * auther ) {
  auther->state             = FD_PRECNF_AUTH_STATE_REQ_CHALLENGE;
  auther->needs_poll        = 1;
  auther->access_token_sz   = 0;
  auther->refresh_token_sz  = 0;
  auther->access_expiry_ns  = 0L;
  auther->refresh_expiry_ns = 0L;
}

void
fd_precnf_auther_set_pubkey( fd_precnf_auther_t * auther,
                             uchar const          pubkey[ 32 ] ) {
  fd_memcpy( auther->pubkey, pubkey, 32UL );
}

static long
token_expiry_ns( auth_Token const * token ) {
  return token->expires_at_utc.seconds*(long)1e9 + (long)token->expires_at_utc.nanos;
}

/* A usable token has a value, an expiry, and has not expired yet. */

static int
token_valid( auth_Token const * token,
             ulong              max_sz,
             long               now,
             char const *       kind ) {
  if( FD_UNLIKELY( !token->value.size ) ) {
    FD_LOG_WARNING(( "precnf auth: missing %s token", kind ));
    return 0;
  }
  if( FD_UNLIKELY( token->value.size>max_sz ) ) {
    FD_LOG_WARNING(( "precnf auth: oversized %s token (%u bytes)", kind, token->value.size ));
    return 0;
  }
  if( FD_UNLIKELY( !token->has_expires_at_utc ) ) {
    FD_LOG_WARNING(( "precnf auth: %s token has no expiry", kind ));
    return 0;
  }
  if( FD_UNLIKELY( token_expiry_ns( token )<=now ) ) {
    FD_LOG_WARNING(( "precnf auth: %s token is already expired", kind ));
    return 0;
  }
  return 1;
}

static void
auth_fail( fd_precnf_auther_t * auther ) {
  auther->fail_cnt++;
  fd_precnf_auther_reset( auther );
}

static void
req_challenge( fd_precnf_auther_t * auther,
               fd_grpc_client_t *   client,
               long                 now ) {
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( client ) ) ) return;

  auth_GenerateAuthChallengeRequest req = {0};
  req.role = auth_Role_RELAYER;
  memcpy( req.pubkey.bytes, auther->pubkey, 32UL );
  req.pubkey.size = 32UL;

  static char const path[] = "/auth.AuthService/GenerateAuthChallenge";
  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      client, path, sizeof(path)-1, FD_PRECNF_REQ_AUTH_CHALLENGE,
      &auth_GenerateAuthChallengeRequest_msg, &req, NULL, 0, 0 /* unary */ );
  if( FD_UNLIKELY( !request ) ) return;
  fd_grpc_client_deadline_set( request, FD_GRPC_DEADLINE_RX_END, now+FD_PRECNF_AUTH_REQUEST_TIMEOUT_NS );

  auther->state      = FD_PRECNF_AUTH_STATE_WAIT_CHALLENGE;
  auther->needs_poll = 0;

  char key_cstr[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( auther->pubkey, NULL, key_cstr );
  FD_LOG_INFO(( "precnf: requesting relayer auth challenge (identity=%s)", key_cstr ));
}

static void
req_tokens( fd_precnf_auther_t *   auther,
            fd_grpc_client_t *     client,
            fd_keyguard_client_t * keyguard,
            long                   now ) {
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( client ) ) ) return;

  auth_GenerateAuthTokensRequest req = {0};

  /* Format challenge string as '{base58(pubkey)}-{challenge}' */
  ulong enc_len;
  char * p = (char *)req.challenge.bytes;
  fd_base58_encode_32( auther->pubkey, &enc_len, p );
  p += enc_len;
  p = fd_cstr_append_char( p, '-' );
  p = fd_cstr_append_text( p, auther->challenge, 9UL );
  req.challenge.size = (uint)( (ulong)p - (ulong)req.challenge.bytes );

  memcpy( req.client_pubkey.bytes, auther->pubkey, 32UL );
  req.client_pubkey.size = 32UL;

  /* The sign tile signs "<base58 pubkey>-<challenge>" for this sign type. */
  fd_keyguard_client_sign( keyguard, req.signed_challenge.bytes, (uchar const *)auther->challenge, 9UL,
                           FD_KEYGUARD_SIGN_TYPE_PUBKEY_CONCAT_ED25519 );
  req.signed_challenge.size = 64UL;

  static char const path[] = "/auth.AuthService/GenerateAuthTokens";
  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      client, path, sizeof(path)-1, FD_PRECNF_REQ_AUTH_TOKENS,
      &auth_GenerateAuthTokensRequest_msg, &req, NULL, 0, 0 /* unary */ );
  if( FD_UNLIKELY( !request ) ) return;
  fd_grpc_client_deadline_set( request, FD_GRPC_DEADLINE_RX_END, now+FD_PRECNF_AUTH_REQUEST_TIMEOUT_NS );

  auther->state      = FD_PRECNF_AUTH_STATE_WAIT_TOKENS;
  auther->needs_poll = 0;
}

static void
req_refresh( fd_precnf_auther_t * auther,
             fd_grpc_client_t *   client,
             long                 now ) {
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( client ) ) ) return;

  auth_RefreshAccessTokenRequest req = {0};
  memcpy( req.refresh_token.bytes, auther->refresh_token, auther->refresh_token_sz );
  req.refresh_token.size = auther->refresh_token_sz;

  static char const path[] = "/auth.AuthService/RefreshAccessToken";
  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      client, path, sizeof(path)-1, FD_PRECNF_REQ_AUTH_REFRESH,
      &auth_RefreshAccessTokenRequest_msg, &req, NULL, 0, 0 /* unary */ );
  if( FD_UNLIKELY( !request ) ) return;
  fd_grpc_client_deadline_set( request, FD_GRPC_DEADLINE_RX_END, now+FD_PRECNF_AUTH_REQUEST_TIMEOUT_NS );

  auther->state      = FD_PRECNF_AUTH_STATE_WAIT_REFRESH;
  auther->needs_poll = 0;
}

void
fd_precnf_auther_poll( fd_precnf_auther_t *   auther,
                       fd_grpc_client_t *     client,
                       fd_keyguard_client_t * keyguard,
                       long                   now ) {
  switch( auther->state ) {
  case FD_PRECNF_AUTH_STATE_REQ_CHALLENGE: req_challenge( auther, client, now );           break;
  case FD_PRECNF_AUTH_STATE_REQ_TOKENS:    req_tokens   ( auther, client, keyguard, now ); break;
  case FD_PRECNF_AUTH_STATE_REQ_REFRESH:   req_refresh  ( auther, client, now );           break;
  default: auther->needs_poll = 0; break;
  }
}

void
fd_precnf_auther_check_expiry( fd_precnf_auther_t * auther,
                               long                 now ) {
  if( FD_LIKELY( auther->state!=FD_PRECNF_AUTH_STATE_DONE ) ) return;
  if( FD_UNLIKELY( auther->refresh_expiry_ns-now<FD_PRECNF_AUTH_REFRESH_MARGIN_NS ) ) {
    /* Refresh token about to expire: run the full challenge again. */
    FD_LOG_INFO(( "precnf: refresh token expiring, re-authenticating" ));
    fd_precnf_auther_reset( auther );
  } else if( FD_UNLIKELY( auther->access_expiry_ns-now<FD_PRECNF_AUTH_REFRESH_MARGIN_NS ) ) {
    auther->state      = FD_PRECNF_AUTH_STATE_REQ_REFRESH;
    auther->needs_poll = 1;
  }
}

static void
handle_challenge_resp( fd_precnf_auther_t * auther,
                       void const *         data,
                       ulong                data_sz ) {
  pb_istream_t istream = pb_istream_from_buffer( data, data_sz );
  auth_GenerateAuthChallengeResponse resp = auth_GenerateAuthChallengeResponse_init_default;
  if( FD_UNLIKELY( !pb_decode( &istream, &auth_GenerateAuthChallengeResponse_msg, &resp ) ) ) {
    FD_LOG_WARNING(( "precnf auth: failed to decode GenerateAuthChallengeResponse" ));
    auth_fail( auther );
    return;
  }
  if( FD_UNLIKELY( resp.challenge.size!=9UL ) ) {
    FD_LOG_WARNING(( "precnf auth: unexpected challenge size %u (expected 9)", resp.challenge.size ));
    auth_fail( auther );
    return;
  }
  memcpy( auther->challenge, resp.challenge.bytes, 9UL );
  auther->state      = FD_PRECNF_AUTH_STATE_REQ_TOKENS;
  auther->needs_poll = 1;
}

static void
handle_tokens_resp( fd_precnf_auther_t * auther,
                    void const *         data,
                    ulong                data_sz,
                    long                 now ) {
  pb_istream_t istream = pb_istream_from_buffer( data, data_sz );
  auth_GenerateAuthTokensResponse resp = auth_GenerateAuthTokensResponse_init_default;
  if( FD_UNLIKELY( !pb_decode( &istream, &auth_GenerateAuthTokensResponse_msg, &resp ) ) ) {
    FD_LOG_WARNING(( "precnf auth: failed to decode GenerateAuthTokensResponse" ));
    auth_fail( auther );
    return;
  }
  if( FD_UNLIKELY( !resp.has_access_token || !resp.has_refresh_token ||
                   !token_valid( &resp.access_token,  sizeof(auther->access_token),  now, "access"  ) ||
                   !token_valid( &resp.refresh_token, sizeof(auther->refresh_token), now, "refresh" ) ) ) {
    auth_fail( auther );
    return;
  }
  fd_memcpy( auther->access_token,  resp.access_token.value.bytes,  resp.access_token.value.size  );
  fd_memcpy( auther->refresh_token, resp.refresh_token.value.bytes, resp.refresh_token.value.size );
  auther->access_token_sz   = (ushort)resp.access_token.value.size;
  auther->refresh_token_sz  = (ushort)resp.refresh_token.value.size;
  auther->access_expiry_ns  = token_expiry_ns( &resp.access_token  );
  auther->refresh_expiry_ns = token_expiry_ns( &resp.refresh_token );
  auther->state             = FD_PRECNF_AUTH_STATE_DONE;
  auther->needs_poll        = 0;
  auther->auth_cnt++;
  FD_LOG_INFO(( "precnf: relayer auth succeeded (access token valid %ld s, refresh token %ld s)",
                (auther->access_expiry_ns-now)/(long)1e9, (auther->refresh_expiry_ns-now)/(long)1e9 ));
}

static void
handle_refresh_resp( fd_precnf_auther_t * auther,
                     void const *         data,
                     ulong                data_sz,
                     long                 now ) {
  pb_istream_t istream = pb_istream_from_buffer( data, data_sz );
  auth_RefreshAccessTokenResponse resp = auth_RefreshAccessTokenResponse_init_default;
  if( FD_UNLIKELY( !pb_decode( &istream, &auth_RefreshAccessTokenResponse_msg, &resp ) ||
                   !resp.has_access_token ||
                   !token_valid( &resp.access_token, sizeof(auther->access_token), now, "refreshed access" ) ) ) {
    FD_LOG_WARNING(( "precnf auth: refresh failed, re-authenticating" ));
    auth_fail( auther );
    return;
  }
  fd_memcpy( auther->access_token, resp.access_token.value.bytes, resp.access_token.value.size );
  auther->access_token_sz  = (ushort)resp.access_token.value.size;
  auther->access_expiry_ns = token_expiry_ns( &resp.access_token );
  auther->state            = FD_PRECNF_AUTH_STATE_DONE;
  auther->needs_poll       = 0;
  auther->refresh_cnt++;
  FD_LOG_INFO(( "precnf: relayer access token refreshed (valid %ld s)", (auther->access_expiry_ns-now)/(long)1e9 ));
}

void
fd_precnf_auther_handle_resp( fd_precnf_auther_t * auther,
                              ulong                request_ctx,
                              void const *         data,
                              ulong                data_sz,
                              long                 now ) {
  switch( request_ctx ) {
  case FD_PRECNF_REQ_AUTH_CHALLENGE:
    if( FD_LIKELY( auther->state==FD_PRECNF_AUTH_STATE_WAIT_CHALLENGE ) ) handle_challenge_resp( auther, data, data_sz );
    break;
  case FD_PRECNF_REQ_AUTH_TOKENS:
    if( FD_LIKELY( auther->state==FD_PRECNF_AUTH_STATE_WAIT_TOKENS ) ) handle_tokens_resp( auther, data, data_sz, now );
    break;
  case FD_PRECNF_REQ_AUTH_REFRESH:
    if( FD_LIKELY( auther->state==FD_PRECNF_AUTH_STATE_WAIT_REFRESH ) ) handle_refresh_resp( auther, data, data_sz, now );
    break;
  default:
    break;
  }
}

void
fd_precnf_auther_handle_request_fail( fd_precnf_auther_t * auther,
                                      ulong                request_ctx ) {
  switch( request_ctx ) {
  case FD_PRECNF_REQ_AUTH_CHALLENGE:
  case FD_PRECNF_REQ_AUTH_TOKENS:
  case FD_PRECNF_REQ_AUTH_REFRESH:
    FD_LOG_WARNING(( "precnf auth: request %lu failed", request_ctx ));
    auth_fail( auther );
    break;
  default:
    break;
  }
}

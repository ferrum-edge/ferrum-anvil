//! HTTP/3 execution policy: forced H3 never falls back silently; automatic
//! mode records the failed H3 attempt and the TCP fallback as separate
//! attempts. The fallback is a new attempt of the engine's loop, with reason
//! `protocol_fallback{from: "h3"}`, so its per-send auth (HMAC nonce, DPoP
//! proof, JWT time claims) is signed again like any other attempt's. It is
//! made only when sending the request again is safe (see [`tcp_fallback`]).

use anvil_domain::execution::DispatchState;
use anvil_domain::settings::HttpVersionPolicy;

/// What follows an HTTP/3 attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum H3Fallback {
    /// No fallback: forced HTTP/3, a response arrived, or the execution was
    /// canceled.
    None,
    /// Send the request over TCP as a new attempt, signed again.
    Tcp,
    /// The request may have been received over HTTP/3 and its method is not
    /// idempotent: it is not sent again over TCP.
    NotResent,
}

/// Whether the automatic policy sends the request again over TCP after an
/// HTTP/3 attempt for `method` that ended with `dispatch`, and failed without
/// a response when `failed_without_response`. Only `not_dispatched` proves
/// that nothing of the request was sent over HTTP/3: the connection or the
/// handshake failed before the request stream was opened, or the server
/// refused its 0-RTT early data unread and the transport's send after the
/// handshake did not start. Any other state, `unknown` included, counts as
/// possibly received, and only an idempotent method (the retry policy's
/// definition) is then sent again.
pub fn tcp_fallback(
    policy: HttpVersionPolicy,
    failed_without_response: bool,
    dispatch: DispatchState,
    method: &str,
    canceled: bool,
) -> H3Fallback {
    if policy != HttpVersionPolicy::Http3WithFallback || !failed_without_response || canceled {
        H3Fallback::None
    } else if dispatch == DispatchState::NotDispatched || anvil_diagnostics::facts::is_idempotent(method) {
        H3Fallback::Tcp
    } else {
        H3Fallback::NotResent
    }
}

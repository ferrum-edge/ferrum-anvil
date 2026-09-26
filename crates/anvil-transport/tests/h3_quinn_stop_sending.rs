//! The vendored `h3-quinn` receive stream (`vendor/README.md`) against real
//! quinn endpoints. While a read waits for data, that read owns the QUIC
//! stream; `stop_sending` must still stop the stream with the requested code
//! at once. h3-quinn 0.0.10 panicked there (a canceled HTTP/3 call hit it),
//! and later releases hold the code until the peer sends again, so after a
//! cancel quinn stops the dropped stream with code 0 instead.

use anvil_fixtures::{LabPki, TlsServerOptions};
use bytes::Bytes;
use h3::quic::{self, RecvStream as _};
use std::future::poll_fn;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

/// A client connection to a local QUIC server, and the server's side of it.
async fn connected() -> (quinn::Connection, quinn::Connection) {
    let pki = LabPki::generate();
    let mut opts = TlsServerOptions::new(pki.server.chain_with(&pki.ca), pki.server.key.clone());
    opts.alpn = vec!["h3".into()];
    opts.tls13_only = true;
    let server_tls = quinn::crypto::rustls::QuicServerConfig::try_from(anvil_fixtures::tlsserver::server_config(&opts).unwrap()).unwrap();
    let server = quinn::Endpoint::server(quinn::ServerConfig::with_crypto(Arc::new(server_tls)), "127.0.0.1:0".parse().unwrap()).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for c in anvil_fixtures::tlsserver::certs(&pki.ca.cert) {
        roots.add(c).unwrap();
    }
    let mut client_tls = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];
    let client_tls = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap();
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_tls)));
    let addr = server.local_addr().unwrap();
    tokio::join!(
        async { client.connect(addr, "localhost").unwrap().await.unwrap() },
        async { server.accept().await.unwrap().await.unwrap() },
    )
}

#[tokio::test]
async fn stop_sending_during_a_pending_read_sends_the_code_at_once() {
    anvil_transport::init();
    let (client_conn, server_conn) = connected().await;
    // The server opens a stream and sends one byte, then nothing more.
    let mut send = server_conn.open_uni().await.unwrap();
    send.write_all(b"x").await.unwrap();
    let mut conn = h3_quinn::Connection::new(client_conn.clone());
    let mut recv = poll_fn(|cx| <h3_quinn::Connection as quic::Connection<Bytes>>::poll_accept_recv(&mut conn, cx)).await.unwrap();
    let id = recv.recv_id();
    let first = poll_fn(|cx| recv.poll_data(cx)).await.unwrap().unwrap();
    assert_eq!(&first[..], b"x");
    // The next read waits for data and takes the QUIC stream with it.
    assert!(poll_fn(|cx| Poll::Ready(recv.poll_data(cx))).await.is_pending());
    assert_eq!(recv.recv_id(), id);
    let cancelled = h3::error::Code::H3_REQUEST_CANCELLED.value();
    recv.stop_sending(cancelled);
    // `recv` is still alive, so this STOP_SENDING came from `stop_sending`,
    // not from quinn dropping the stream.
    let stopped = tokio::time::timeout(Duration::from_secs(5), send.stopped()).await.expect("no STOP_SENDING while the stream was open");
    assert_eq!(stopped.unwrap(), Some(quinn::VarInt::from_u64(cancelled).unwrap()));
    drop(recv);
}

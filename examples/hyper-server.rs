//! A sample Hyper server using this crate for TLS connections
//!
//! You can test this out by running:
//!
//!     cargo run --example hyper-server
//!
//! and it should print out an address that it's listening on. You can then
//! connect to this server via HTTP to see "Hello, world!". Note that the TLS
//! certificate used here is an invalid one, so you'll have to ignore
//! certificate errors, such as with:
//!
//!     curl -k https://localhost:12345

extern crate futures;
extern crate hyper;
extern crate native_tls;
extern crate tokio;
extern crate tokio_tls;

use std::io;

use futures::future::Future;
use futures::stream::Stream;
use hyper::server::conn::Http;
use hyper::service::service_fn_ok;
use hyper::{Body, Response};
use native_tls::{Identity, TlsAcceptor};
use tokio::net::TcpListener;

pub fn main() {
    // Create our TLS context through which new connections will be
    // accepted. This is where we pass in the certificate as well to
    // send to clients.
    let der = include_bytes!("identity.p12");
    let cert = Identity::from_pkcs12(der, "mypass").unwrap();
    let tls_cx = TlsAcceptor::builder(cert).build().unwrap();
    let tls_cx = tokio_tls::TlsAcceptor::from(tls_cx);

    let new_service = || service_fn_ok(|_req| Response::new(Body::from("Hello World")));

    let addr = "127.0.0.1:12345".parse().unwrap();
    let srv = TcpListener::bind(&addr).expect("Error binding local port");
    // Use lower lever hyper API to be able to intercept client connection
    let http_proto = Http::new();
    let http_server = http_proto
        .serve_incoming(
            srv.incoming().and_then(move |socket| {
                tls_cx
                    .accept(socket)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
            }),
            new_service,
        )
        .then(|res| {
            match res {
                Ok(conn) => Ok(Some(conn)),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    Ok(None)
                },
            }
        })
        .for_each(|conn_opt| {
            if let Some(conn) = conn_opt {
                hyper::rt::spawn(
                    conn.and_then(|c| c.map_err(|e| panic!("Hyper error {}", e)))
                        .map_err(|e| eprintln!("Connection error {}", e)),
                );
            }

            Ok(())
        });

    println!("Listening on {}", addr);

    hyper::rt::run(http_server);
}

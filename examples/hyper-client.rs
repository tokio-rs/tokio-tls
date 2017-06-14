//! A sample Hyper client using this crate for TLS connections
//!
//! You can test this out by running:
//!
//!     cargo run --example hyper-client
//!
//! and on stdout you should see rust-lang.org's headers and web page.
//!
//! Note that there's also the `hyper-tls` crate which may be useful.

extern crate futures;
extern crate hyper;
extern crate native_tls;
extern crate tokio_core;
extern crate tokio_service;
extern crate tokio_tls;

use std::io;
use std::sync::Arc;

use futures::future::{err, Future};
use futures::stream::Stream;
use hyper::client::HttpConnector;
use hyper::{Client, Request, Method, Uri};
use native_tls::TlsConnector;
use tokio_core::net::TcpStream;
use tokio_core::reactor::Core;
use tokio_service::Service;
use tokio_tls::{TlsConnectorExt, TlsStream};

fn main() {
    let mut core = Core::new().unwrap();

    // Create a custom "connector" for Hyper which will route connections
    // through the `TlsConnector` we create here after routing them through
    // `HttpConnector` first.
    let tls_cx = TlsConnector::builder().unwrap().build().unwrap();
    let mut connector = HttpsConnector {
        tls: Arc::new(tls_cx),
        http: HttpConnector::new(2, &core.handle()),
    };
    connector.http.enforce_http(false);
    let client = Client::configure()
                    .connector(connector)
                    .build(&core.handle());

    // Send off a request for Rust's home page, fetched over TLS. Note that
    // this'll just fetch the headers, the body won't be downloaded yet.
    let uri = "https://www.rust-lang.org/".parse().unwrap();
    let req = Request::new(Method::Get, uri);
    let response = core.run(client.request(req)).unwrap();
    println!("{} {}", response.version(), response.status());
    for header in response.headers().iter() {
        print!("{}", header);
    }

    // Finish off our request by fetching all of the body.
    let body = core.run(response.body().concat2()).unwrap();
    println!("{}", String::from_utf8_lossy(&body));
}

struct HttpsConnector {
    tls: Arc<TlsConnector>,
    http: HttpConnector,
}

impl Service for HttpsConnector {
    type Request = Uri;
    type Response = TlsStream<TcpStream>;
    type Error = io::Error;
    type Future = Box<Future<Item = Self::Response, Error = io::Error>>;

    fn call(&self, uri: Uri) -> Self::Future {
        // Right now this is intended to showcase `https`, but you could
        // also adapt this to return something like `MaybeTls<T>` where
        // some clients resolve to TLS streams (https) and others resolve
        // to normal TCP streams (http)
        if uri.scheme() != Some("https") {
            return err(io::Error::new(io::ErrorKind::Other,
                                      "only works with https")).boxed()
        }

        // Look up the host that we're connecting to as we're going to validate
        // this as part of the TLS handshake.
        let host = match uri.host() {
            Some(s) => s.to_string(),
            None =>  {
                return err(io::Error::new(io::ErrorKind::Other,
                                          "missing host")).boxed()
            }
        };

        // Delegate to the standard `HttpConnector` type to create a connected
        // TCP socket. Once we've got that socket initiate the TLS handshake
        // with the host name that's provided in the URI we extracted above.
        let tls_cx = self.tls.clone();
        Box::new(self.http.call(uri).and_then(move |tcp| {
            tls_cx.connect_async(&host, tcp)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
        }))
    }
}

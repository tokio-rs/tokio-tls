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
extern crate tokio;
extern crate tokio_tls;

use std::io;
use std::sync::Arc;

use futures::future::{err, Future};
use futures::stream::Stream;
use hyper::client::{HttpConnector};
use hyper::client::connect::{Connect, Connected, Destination};
use hyper::Body;
use hyper::{Client, Request};
use native_tls::TlsConnector;
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio_tls::{TlsConnectorExt, TlsStream};

fn main() {
    let mut runtime = Runtime::new().unwrap();

    // Create a custom "connector" for Hyper which will route connections
    // through the `TlsConnector` we create here after routing them through
    // `HttpConnector` first.
    let tls_cx = TlsConnector::builder().build().unwrap();
    let mut connector = HttpsConnector {
        tls: Arc::new(tls_cx),
        http: HttpConnector::new(2),
    };
    connector.http.enforce_http(false);
    let client = Client::builder()
                    .build(connector);

    // Send off a request for Rust's home page, fetched over TLS. Note that
    // this'll just fetch the headers, the body won't be downloaded yet.
    let req = Request::builder()
        .uri("https://www.rust-lang.org/")
        .header("User-Agent", "hyper-client-example/1.0")
        .body(Body::empty())
        .unwrap();
    let response = runtime.block_on(client.request(req)).unwrap();
    println!("{:?} {}", response.version(), response.status());
    for header in response.headers().iter() {
        print!("{:?}\n", header);
    }

    // Finish off our request by fetching all of the body.
    let body = runtime.block_on(response.into_body().concat2()).unwrap();
    println!("{}", String::from_utf8_lossy(&body));
}

struct HttpsConnector {
    tls: Arc<TlsConnector>,
    http: HttpConnector,
}

impl Connect for HttpsConnector {
    type Transport = TlsStream<TcpStream>;
    type Error = io::Error;
    type Future =  Box<Future<Item = (Self::Transport, Connected), Error = Self::Error> + Send>;

    fn connect(&self, dst: Destination) -> Self::Future {

        if dst.scheme() != "https" {
            return Box::new(err(io::Error::new(io::ErrorKind::Other,
                                      "only works with https")))
        }

        let host = format!("{}{}", dst.host(), dst.port().map(|p| format!(":{}",p)).unwrap_or("".into()));

        let tls_cx = self.tls.clone();
        Box::new(self.http.connect(dst).and_then(move |(tcp, connected)| {
            tls_cx.connect_async(&host, tcp)
                .map(|s| (s, connected))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
        }))

    }


}


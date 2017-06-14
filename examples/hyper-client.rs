//! A sample Hyper client using this crate for TLS connections
//!
//! You can test this out by running:
//!
//!     cargo run --example hyper-client
//!
//! and on stdout you should see rust-lang.org's headers and web page.

extern crate futures;
extern crate futures_cpupool;
extern crate hyper;
extern crate native_tls;
extern crate tokio_core;
extern crate tokio_service;
extern crate tokio_tls;

use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use futures::future::{err, ok, Future};
use futures::stream::Stream;
use futures_cpupool::CpuPool;
use hyper::{Client, Request, Method, Uri};
use native_tls::TlsConnector;
use tokio_core::net::TcpStream;
use tokio_core::reactor::{Core, Handle};
use tokio_service::Service;
use tokio_tls::{TlsConnectorExt, TlsStream};

fn main() {
    let mut core = Core::new().unwrap();

    // Create a custom "connector" for Hyper which will route connections
    // through the `TlsConnector` we create here.
    let tls_cx = TlsConnector::builder().unwrap().build().unwrap();
    let connector = Https {
        tls_connector: Arc::new(tls_cx),
        dns_pool: CpuPool::new(1),
        handle: core.handle(),
    };
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

struct Https {
    tls_connector: Arc<TlsConnector>,
    dns_pool: CpuPool,
    handle: Handle,
}

impl Service for Https {
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

        // Figure out what address we're connecting to. We parse out the
        // host of the URI along with the port. If the host doesn't look
        // like an IP address then we fall back to blocking DNS resolution
        // on our thread pool. You could imagine plugging in a truly
        // asynchronous resolver here as well.
        //
        // Eventually though at the end we're doing all this to resolve to
        // a `SocketAddr` instance to create a TCP connection to.
        let host = match uri.host() {
            Some(s) => s,
            None =>  {
                return err(io::Error::new(io::ErrorKind::Other,
                                          "missing host")).boxed()
            }
        };
        let port = uri.port().unwrap_or(443);
        let addr = match host.parse::<IpAddr>() {
            Ok(addr) => Box::new(ok(addr)) as Box<Future<Item=_, Error=_>>,
            Err(_) => {
                let host = host.to_string();
                Box::new(self.dns_pool.spawn_fn(move || {
                    let host = format!("{}:443", host);
                    host.to_socket_addrs()?
                        .next()
                        .map(|addr| addr.ip())
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::Other,
                                           "failed to resolve to an addr")
                        })
                }))
            }
        };
        let addr = addr.map(move |addr| SocketAddr::new(addr, port));

        // Given our `SocketAddr` we computed above, issue a TCP connection
        // and wait for the client to get connected.
        let handle = self.handle.clone();
        let tcp = addr.and_then(move |addr| {
            TcpStream::connect(&addr, &handle)
        });

        // And now finally, once we've connected a TCP socket, perform the
        // TLS handshake over the socket. This uses the `connect_async`
        // method to perform the TLS handshake.
        let host = host.to_string();
        let tls_cx = self.tls_connector.clone();
        Box::new(tcp.and_then(move |tcp| {
            tls_cx.connect_async(&host, tcp)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
        }))
    }
}

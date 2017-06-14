//! A sample Hyper server using this crate for TLS connections
//!
//! You can test this out by running:
//!
//!     cargo run --example hyper-server --features tokio-proto
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
extern crate tokio_service;
extern crate tokio_tls;

fn main() {
    imp::main();
}

#[cfg(feature = "tokio-proto")]
mod imp {
    extern crate tokio_proto;

    use std::io;

    use futures::future::{ok, Future};
    use hyper::server::Http;
    use hyper::{Request, Response, StatusCode};
    use native_tls::{TlsAcceptor, Pkcs12};
    use self::tokio_proto::TcpServer;
    use tokio_service::Service;
    use tokio_tls::proto;

    pub fn main() {
        // Create our TLS context through which new connections will be
        // accepted. This is where we pass in the certificate as well to
        // send to clients.
        let der = include_bytes!("identity.p12");
        let cert = Pkcs12::from_der(der, "mypass").unwrap();
        let tls_cx = TlsAcceptor::builder(cert).unwrap()
                                .build().unwrap();

        // Wrap up hyper's `Http` protocol in our own `Server` protocol. This
        // will run hyper's protocol and then wrap the result in a TLS stream,
        // performing a TLS handshake with connected clients.
        let proto = proto::Server::new(Http::new(), tls_cx);

        // Finally use `tokio-proto`'s `TcpServer` helper struct to quickly
        // take our protocol above to running our hello-world Service on a
        // local TCP port.
        let addr = "127.0.0.1:12345".parse().unwrap();
        let srv = TcpServer::new(proto, addr);
        println!("Listening on {}", addr);
        srv.serve(|| Ok(Hello));
    }

    struct Hello;

    impl Service for Hello {
        type Request = Request;
        type Response = Response;
        type Error = io::Error;
        type Future = Box<Future<Item = Response, Error = io::Error>>;

        fn call(&self, req: Request) -> Self::Future {
            drop(req);
            Box::new(ok(Response::new()
                            .with_status(StatusCode::Ok)
                            .with_body("Hello, world!\n")))
        }
    }
}

#[cfg(not(feature = "tokio-proto"))]
mod imp {
    pub fn main() {
        println!("this example requires the `tokio-proto` feature to be enabled");
    }
}


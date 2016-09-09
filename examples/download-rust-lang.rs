extern crate futures;
extern crate tokio_core;
extern crate tokio_tls;

use std::net::ToSocketAddrs;

use futures::Future;
use tokio_core::reactor::Core;
use tokio_core::net::TcpStream;
use tokio_tls::ClientContext;

fn main() {
    let mut core = Core::new().unwrap();
    let addr = "www.rust-lang.org:443".to_socket_addrs().unwrap().next().unwrap();

    let socket = TcpStream::connect(&addr, &core.handle());

    let tls_handshake = socket.and_then(|socket| {
        let cx = ClientContext::new().unwrap();
        cx.handshake("www.rust-lang.org", socket)
    });
    let request = tls_handshake.and_then(|socket| {
        tokio_core::io::write_all(socket, "\
            GET / HTTP/1.0\r\n\
            Host: www.rust-lang.org\r\n\
            \r\n\
        ".as_bytes())
    });
    let response = request.and_then(|(socket, _)| {
        tokio_core::io::read_to_end(socket, Vec::new())
    });

    let (_, data) = core.run(response).unwrap();
    println!("{}", String::from_utf8_lossy(&data));
}

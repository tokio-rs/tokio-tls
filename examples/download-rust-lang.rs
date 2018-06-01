extern crate futures;
extern crate native_tls;
extern crate tokio;
extern crate tokio_io;
extern crate tokio_tls;

use std::io;
use std::net::ToSocketAddrs;

use futures::Future;
use native_tls::TlsConnector;
use tokio::net::TcpStream;
use tokio_tls::TlsConnectorExt;

fn main() {
    let addr = "www.rust-lang.org:443".to_socket_addrs().unwrap().next().unwrap();

    let socket = TcpStream::connect(&addr);
    let cx = TlsConnector::builder().unwrap().build().unwrap();

    let tls_handshake = socket.and_then(move |socket| {
        cx.connect_async("www.rust-lang.org", socket).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, e)
        })
    });
    let request = tls_handshake.and_then(|socket| {
        tokio_io::io::write_all(socket, "\
            GET / HTTP/1.0\r\n\
            Host: www.rust-lang.org\r\n\
            \r\n\
        ".as_bytes())
    });
    let response = request.and_then(|(socket, _)| {
        tokio_io::io::read_to_end(socket, Vec::new())
    });

    //let (_, data) = core.run(response).unwrap();
    //println!("{}", String::from_utf8_lossy(&data));

    tokio::run(response.map(|_| ()).map_err(|_| ()));
}

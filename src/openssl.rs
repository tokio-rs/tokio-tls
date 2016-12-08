extern crate openssl;
extern crate futures;

use std::io::{self, Read, Write, Error, ErrorKind};
use std::mem;

use self::openssl::pkey::PKeyRef;
use self::openssl::ssl::{self, SslMethod};
use self::openssl::x509::X509Ref;
use futures::{Poll, Future, Async};
use tokio_core::io::Io;

pub struct ServerContext {
    inner: ssl::SslAcceptorBuilder,
}

pub struct ClientContext {
    inner: ssl::SslConnectorBuilder,
}

impl ServerContext {
    pub fn handshake<S>(self, stream: S) -> ServerHandshake<S>
        where S: Io,
    {
        let secure_stream = self.inner.build().accept(stream);
        debug!("server handshake");
        ServerHandshake {
            inner: Handshake::new(secure_stream),
        }
    }
}

impl ClientContext {
    pub fn new() -> io::Result<ClientContext> {
        let cx = try!(ssl::SslConnectorBuilder::new(SslMethod::tls()));
        Ok(ClientContext { inner: cx })
    }

    pub fn handshake<S>(self, domain: &str, stream: S) -> ClientHandshake<S>
        where S: Io,
    {
        // see rust-native-tls for the specifics here
        debug!("client handshake with {:?}", domain);
        let secure_stream = self.inner.build().connect(domain, stream);
        ClientHandshake { inner: Handshake::new(secure_stream) }
    }
}

pub struct ClientHandshake<S> {
    inner: Handshake<S>,
}

pub struct ServerHandshake<S> {
    inner: Handshake<S>,
}

enum Handshake<S> {
    Error(io::Error),
    Stream(ssl::SslStream<S>),
    Interrupted(ssl::MidHandshakeSslStream<S>),
    Empty,
}

impl<S> Handshake<S> {
    fn new(res: Result<ssl::SslStream<S>, ssl::HandshakeError<S>>)
           -> Handshake<S> {
        match res {
            Ok(s) => Handshake::Stream(s),
            Err(ssl::HandshakeError::SetupFailure(stack)) => {
                Handshake::Error(translate_ssl(stack))
            }
            Err(ssl::HandshakeError::Failure(e)) => {
                Handshake::Error(Error::new(ErrorKind::Other, e.into_error()))
            }
            Err(ssl::HandshakeError::Interrupted(s)) => {
                Handshake::Interrupted(s)
            }
        }
    }
}

impl<S: Io> Future for ClientHandshake<S> {
    type Item = TlsStream<S>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<TlsStream<S>, io::Error> {
        self.inner.poll()
    }
}

impl<S: Io> Future for ServerHandshake<S> {
    type Item = TlsStream<S>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<TlsStream<S>, io::Error> {
        self.inner.poll()
    }
}

impl<S: Io> Future for Handshake<S> {
    type Item = TlsStream<S>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<TlsStream<S>, io::Error> {
        debug!("let's see how the handshake went");
        let stream = match mem::replace(self, Handshake::Empty) {
            Handshake::Error(e) => return Err(e),
            Handshake::Empty => panic!("can't poll handshake twice"),
            Handshake::Stream(s) => return Ok(Async::Ready(TlsStream::new(s))),
            Handshake::Interrupted(s) => s,
        };

        // TODO: dedup with Handshake::new
        debug!("openssl handshake again");
        match stream.handshake() {
            Ok(s) => Ok(Async::Ready(TlsStream::new(s))),
            Err(ssl::HandshakeError::SetupFailure(stack)) =>
                Err(translate_ssl(stack)),
            Err(ssl::HandshakeError::Failure(e)) => {
                debug!("openssl handshake failure: {}", e.error());
                Err(Error::new(ErrorKind::Other, e.into_error()))
            }
            Err(ssl::HandshakeError::Interrupted(s)) => {
                debug!("handshake not completed");
                *self = Handshake::Interrupted(s);
                Ok(Async::NotReady)
            }
        }
    }
}

fn translate_ssl(err: openssl::error::ErrorStack) -> Error {
    Error::new(io::ErrorKind::Other, err)
}

fn translate(err: openssl::ssl::Error) -> Error {
    match err {
        openssl::ssl::Error::WantRead(i) |
        openssl::ssl::Error::WantWrite(i) => return i,
        _ => Error::new(io::ErrorKind::Other, err),
    }
}

pub struct TlsStream<S> {
    inner: ssl::SslStream<S>,
}

impl<S> TlsStream<S> {
    fn new(s: ssl::SslStream<S>) -> TlsStream<S> {
        TlsStream {
            inner: s,
        }
    }
}

impl<S: Io> Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.ssl_read(buf).map_err(translate)
    }
}

impl<S: Io> Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.ssl_write(buf).map_err(translate)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<S: Io> Io for TlsStream<S> {
    // TODO: more fine-tuned poll_read/poll_write
}

/// Extension trait for servers backed by OpenSSL.
pub trait ServerContextExt: Sized {
    /// Creates a new server context given the public/private key pair.
    ///
    /// This will create a new server connection which will send `cert` to
    /// clients and use `key` as the corresponding private key to encrypt and
    /// sign communications.
    fn new(cert: &X509Ref, key: &PKeyRef) -> io::Result<Self>;

    /// Gets a mutable reference to the underlying SSL context, allowing further
    /// configuration.
    ///
    /// The SSL context here will eventually get used to initiate the server
    /// connection.
    fn ssl_context_mut(&mut self) -> &mut ssl::SslContextBuilder;
}

impl ServerContextExt for ::ServerContext {
    fn new(cert: &X509Ref, key: &PKeyRef) -> io::Result<::ServerContext> {
        let iter = ::std::iter::empty::<X509Ref>();
        let cx =
            try!(ssl::SslAcceptorBuilder::mozilla_intermediate(SslMethod::tls(),
                                                               key,
                                                               cert,
                                                               iter)
                 .map_err(|e| Error::new(ErrorKind::Other, e)));
        Ok(::ServerContext { inner: ServerContext { inner: cx } })
    }

    fn ssl_context_mut(&mut self) -> &mut ssl::SslContextBuilder {
        self.inner.inner.builder_mut()
    }
}

/// Extension trait for clients backed by OpenSSL.
pub trait ClientContextExt {
    /// Gets a mutable reference to the underlying SSL context, allowing further
    /// configuration.
    ///
    /// The SSL context here will eventually get used to initiate the client
    /// connection, and it will otherwise be configured to validate the hostname
    /// given to `handshake` by default.
    fn ssl_context_mut(&mut self) -> &mut ssl::SslContextBuilder;
}

impl ClientContextExt for ::ClientContext {
    fn ssl_context_mut(&mut self) -> &mut ssl::SslContextBuilder {
        self.inner.inner.builder_mut()
    }
}

/// Extension trait for streams backed by OpenSSL.
pub trait TlsStreamExt {
    /// Gets a shared reference to the underlying SSL context, allowing further
    /// configuration and/or inspection of the SSL/TLS state.
    fn ssl_context(&self) -> &ssl::SslRef;
}

impl<S> TlsStreamExt for ::TlsStream<S> {
    fn ssl_context(&self) -> &ssl::SslRef {
        self.inner.inner.ssl()
    }
}

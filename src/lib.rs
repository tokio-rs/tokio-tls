//! Async TLS streams
//!
//! This library is an implementation of TLS streams using the most appropriate
//! system library by default for negotiating the connection. That is, on
//! Windows this library uses SChannel, on OSX it uses SecureTransport, and on
//! other platforms it uses OpenSSL.
//!
//! Each TLS stream implements the `Read` and `Write` traits to interact and
//! interoperate with the rest of the futures I/O ecosystem. Client connections
//! initiated from this crate verify hostnames automatically and by default.
//!
//! This crate primarily exports this ability through two extension traits,
//! `TlsConnectorExt` and `TlsAcceptorExt`. These traits augment the
//! functionality provided by the `native-tls` crate, on which this crate is
//! built. Configuration of TLS parameters is still primarily done through the
//! `native-tls` crate.

#![deny(missing_docs)]
#![doc(html_root_url = "https://docs.rs/tokio-tls/0.1")]

#[cfg_attr(feature = "tokio-proto", macro_use)]
extern crate futures;
extern crate native_tls;
#[macro_use]
extern crate tokio_core;
extern crate tokio_io;

use std::io::{self, Read, Write};

use futures::{Poll, Future, Async};
use native_tls::{HandshakeError, Error, TlsConnector, TlsAcceptor};
#[allow(deprecated)]
use tokio_core::io::Io;
use tokio_io::{AsyncRead, AsyncWrite};

pub mod proto;

/// A wrapper around an underlying raw stream which implements the TLS or SSL
/// protocol.
///
/// A `TlsStream<S>` represents a handshake that has been completed successfully
/// and both the server and the client are ready for receiving and sending
/// data. Bytes read from a `TlsStream` are decrypted from `S` and bytes written
/// to a `TlsStream` are encrypted when passing through to `S`.
#[derive(Debug)]
pub struct TlsStream<S> {
    inner: native_tls::TlsStream<S>,
}

/// Future returned from `TlsConnectorExt::connect_async` which will resolve
/// once the connection handshake has finished.
pub struct ConnectAsync<S> {
    inner: MidHandshake<S>,
}

/// Future returned from `TlsAcceptorExt::accept_async` which will resolve
/// once the accept handshake has finished.
pub struct AcceptAsync<S> {
    inner: MidHandshake<S>,
}

struct MidHandshake<S> {
    inner: Option<Result<native_tls::TlsStream<S>, HandshakeError<S>>>,
}

/// Extension trait for the `TlsConnector` type in the `native_tls` crate.
pub trait TlsConnectorExt: sealed::Sealed {
    /// Connects the provided stream with this connector, assuming the provided
    /// domain.
    ///
    /// This function will internally call `TlsConnector::connect` to connect
    /// the stream and returns a future representing the resolution of the
    /// connection operation. The returned future will resolve to either
    /// `TlsStream<S>` or `Error` depending if it's successful or not.
    ///
    /// This is typically used for clients who have already established, for
    /// example, a TCP connection to a remote server. That stream is then
    /// provided here to perform the client half of a connection to a
    /// TLS-powered server.
    ///
    /// # Compatibility notes
    ///
    /// Note that this method currently requires `S: Read + Write` but it's
    /// highly recommended to ensure that the object implements the `AsyncRead`
    /// and `AsyncWrite` traits as well, otherwise this function will not work
    /// properly.
    fn connect_async<S>(&self, domain: &str, stream: S) -> ConnectAsync<S>
        where S: Read + Write; // TODO: change to AsyncRead + AsyncWrite

    /// Like `connect_async`, but does not validate the server's domain name
    /// against its certificate.
    ///
    /// # Warning
    ///
    /// You should think very carefully before you use this method. If hostname
    /// verification is not  used, *any* valid certificate for *any* site will
    /// be trusted for use from any other. This introduces a significant
    /// vulnerability to man-in-the-middle  attacks.
    ///
    /// # Compatibility notes
    ///
    /// Note that this method currently requires `S: Read + Write` but it's
    /// highly recommended to ensure that the object implements the `AsyncRead`
    /// and `AsyncWrite` traits as well, otherwise this function will not work
    /// properly.
    fn danger_connect_async_without_providing_domain_for_certificate_verification_and_server_name_indication<S>(
            &self, stream: S) -> ConnectAsync<S>
        where S: Read + Write; // TODO: change to AsyncRead + AsyncWrite
}

/// Extension trait for the `TlsAcceptor` type in the `native_tls` crate.
pub trait TlsAcceptorExt: sealed::Sealed {
    /// Accepts a new client connection with the provided stream.
    ///
    /// This function will internally call `TlsAcceptor::accept` to connect
    /// the stream and returns a future representing the resolution of the
    /// connection operation. The returned future will resolve to either
    /// `TlsStream<S>` or `Error` depending if it's successful or not.
    ///
    /// This is typically used after a new socket has been accepted from a
    /// `TcpListener`. That socket is then passed to this function to perform
    /// the server half of accepting a client connection.
    ///
    /// # Compatibility notes
    ///
    /// Note that this method currently requires `S: Read + Write` but it's
    /// highly recommended to ensure that the object implements the `AsyncRead`
    /// and `AsyncWrite` traits as well, otherwise this function will not work
    /// properly.
    fn accept_async<S>(&self, stream: S) -> AcceptAsync<S>
        where S: Read + Write; // TODO: change to AsyncRead + AsyncWrite
}

mod sealed {
    pub trait Sealed {}
}

impl<S> TlsStream<S> {
    /// Get access to the internal `native_tls::TlsStream` stream which also
    /// transitively allows access to `S`.
    pub fn get_ref(&self) -> &native_tls::TlsStream<S> {
        &self.inner
    }

    /// Get mutable access to the internal `native_tls::TlsStream` stream which
    /// also transitively allows mutable access to `S`.
    pub fn get_mut(&mut self) -> &mut native_tls::TlsStream<S> {
        &mut self.inner
    }
}

impl<S: Read + Write> Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<S: Read + Write> Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[allow(deprecated)]
impl<S: Io> Io for TlsStream<S> {
}

impl<S: AsyncRead + AsyncWrite> AsyncRead for TlsStream<S> {
}

impl<S: AsyncRead + AsyncWrite> AsyncWrite for TlsStream<S> {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        try_nb!(self.inner.shutdown());
        self.inner.get_mut().shutdown()
    }
}

impl TlsConnectorExt for TlsConnector {
    fn connect_async<S>(&self, domain: &str, stream: S) -> ConnectAsync<S>
        where S: Read + Write,
    {
        ConnectAsync {
            inner: MidHandshake {
                inner: Some(self.connect(domain, stream)),
            },
        }
    }

    fn danger_connect_async_without_providing_domain_for_certificate_verification_and_server_name_indication<S>(
            &self, stream: S) -> ConnectAsync<S>
        where S: Read + Write,
    {
        ConnectAsync {
            inner: MidHandshake {
                inner: Some(self.danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication(stream)),
            },
        }
    }
}

impl sealed::Sealed for TlsConnector {}

impl TlsAcceptorExt for TlsAcceptor {
    fn accept_async<S>(&self, stream: S) -> AcceptAsync<S>
        where S: Read + Write,
    {
        AcceptAsync {
            inner: MidHandshake {
                inner: Some(self.accept(stream)),
            },
        }
    }
}

impl sealed::Sealed for TlsAcceptor {}

// TODO: change this to AsyncRead/AsyncWrite on next major version
impl<S: Read + Write> Future for ConnectAsync<S> {
    type Item = TlsStream<S>;
    type Error = Error;

    fn poll(&mut self) -> Poll<TlsStream<S>, Error> {
        self.inner.poll()
    }
}

// TODO: change this to AsyncRead/AsyncWrite on next major version
impl<S: Read + Write> Future for AcceptAsync<S> {
    type Item = TlsStream<S>;
    type Error = Error;

    fn poll(&mut self) -> Poll<TlsStream<S>, Error> {
        self.inner.poll()
    }
}

// TODO: change this to AsyncRead/AsyncWrite on next major version
impl<S: Read + Write> Future for MidHandshake<S> {
    type Item = TlsStream<S>;
    type Error = Error;

    fn poll(&mut self) -> Poll<TlsStream<S>, Error> {
        match self.inner.take().expect("cannot poll MidHandshake twice") {
            Ok(stream) => Ok(TlsStream { inner: stream }.into()),
            Err(HandshakeError::Failure(e)) => Err(e),
            Err(HandshakeError::Interrupted(s)) => {
                match s.handshake() {
                    Ok(stream) => Ok(TlsStream { inner: stream }.into()),
                    Err(HandshakeError::Failure(e)) => Err(e),
                    Err(HandshakeError::Interrupted(s)) => {
                        self.inner = Some(Err(HandshakeError::Interrupted(s)));
                        Ok(Async::NotReady)
                    }
                }
            }
        }
    }
}

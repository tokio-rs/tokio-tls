extern crate tokio;
extern crate openssl;

#[macro_use]
extern crate log;

use tokio::io::{Stream, Readiness};
use openssl::crypto::pkey::PKey;
use openssl::ssl::{SSL_OP_NO_SSLV2, SSL_OP_NO_SSLV3, SSL_OP_NO_COMPRESSION};
use openssl::ssl::{self, IntoSsl, SSL_VERIFY_PEER};
use openssl::ssl::Error::{WantRead, WantWrite};
use openssl::x509::X509;
use std::mem;
use std::io::{self, Read, Write};

/// A `Stream` providing SSL/TLS encryption
pub struct SslStream<S> {
    state: State<S>,
    last_read_err: Option<ssl::Error>,
    last_write_err: Option<ssl::Error>,
}

/// A context used to initiate server-side connections of a TLS server.
///
/// Server contexts are typically much harder to create than a client context
/// because they need to know the public/private key that they're going to
/// negotiate the connection with. Specifying these keys is typically done in a
/// very backend-specific method, unfortunately. For that reason there's no
/// `new` constructor.
///
/// For some examples of how to create a context, though, you can take a look at
/// the test suite of `tokio-tls`.
pub struct ServerContext {
    inner: ssl::SslContext,
}

pub struct ClientContext {
    inner: ssl::SslContext,
}

enum State<S> {
    Handshake(Handshake<S>),
    Established(ssl::SslStream<S>),
}

enum Handshake<S> {
    Error(io::Error),
    Stream(ssl::SslStream<S>),
    Interrupted(ssl::MidHandshakeSslStream<S>),
    Empty,
}

/*
 *
 * ===== SslStream =====
 *
 */

impl<S: Stream> SslStream<S> {
    fn is_ready(&self) -> bool {
        if let Some(s) = self.state.established() {
            match self.last_read_err {
                Some(WantRead(..)) => s.get_ref().is_readable(),
                Some(WantWrite(..)) => s.get_ref().is_writable(),
                _ => true,
            }
        } else {
            false
        }
    }

    fn try_complete_handshake(&mut self) -> io::Result<()> {
        let established;

        match self.state {
            State::Handshake(ref mut h) => {
                if let Some(s) = try!(h.try_complete()) {
                    established = s;
                } else {
                    return Ok(());
                }
            }
            _ => return Ok(()),
        }

        self.state = State::Established(established);

        Ok(())
    }
}

impl<S: Stream> Read for SslStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(s) = self.state.established_mut() {
            map_err(&mut self.last_read_err, s.ssl_read(buf))
        } else {
            Err(would_block())
        }
    }
}

impl<S: Stream> Write for SslStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(s) = self.state.established_mut() {
            map_err(&mut self.last_write_err, s.ssl_write(buf))
        } else {
            Err(would_block())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        try!(self.try_complete_handshake());

        if let Some(s) = self.state.established_mut() {
            match s.flush() {
                Ok(()) => Ok(()),
                Err(e) => {
                    if e.kind() == io::ErrorKind::WouldBlock {
                        self.last_write_err = Some(WantWrite(would_block()));
                    }

                    Err(e)
                }
            }
        } else {
            Err(would_block())
        }
    }
}

impl<S: Stream> Readiness for SslStream<S> {
    fn is_readable(&self) -> bool {
        self.is_ready()
    }

    fn is_writable(&self) -> bool {
        self.is_ready()
    }
}

fn map_err<T>(last_err: &mut Option<ssl::Error>,
              res: Result<T, ssl::error::Error>) -> io::Result<T> {

    *last_err = None;

    match res {
        Ok(t) => Ok(t),
        Err(e @ WantRead(..)) => {
            *last_err = Some(e);
            Err(would_block())
        }
        Err(e @ WantWrite(..)) => {
            *last_err = Some(e);
            Err(would_block())
        }
        Err(e) => {
            Err(io::Error::new(io::ErrorKind::Other, e))
        }
    }
}

/*
 *
 * ===== ServerContext =====
 *
 */

impl ServerContext {

    /// Create a new `ServerContext`
    pub fn new(cert: &X509, key: &PKey) -> io::Result<ServerContext> {
        let mut cx = try!(ssl::SslContext::new(ssl::SslMethod::Sslv23)
                              .map_err(translate_ssl));

        // lifted from rust-native-tls
        cx.set_options(SSL_OP_NO_SSLV2 |
                       SSL_OP_NO_SSLV3 |
                       SSL_OP_NO_COMPRESSION);

        let list = "ALL!EXPORT!EXPORT40!EXPORT56!aNULL!LOW!RC4@STRENGTH";
        try!(cx.set_cipher_list(list).map_err(translate_ssl));
        try!(cx.set_certificate(cert).map_err(translate_ssl));
        try!(cx.set_private_key(key).map_err(translate_ssl));
        try!(cx.check_private_key().map_err(translate_ssl));

        Ok(ServerContext { inner: cx })
    }

    /// Performs a handshake with the given I/O stream to resolve to an actual
    /// I/O stream.
    ///
    /// This function will consume this context and return a future which will
    /// either resolve to a `TlsStream<S>` ready for reading/writing if the
    /// handshake completes successfully, or an error if an erroneous event
    /// otherwise happens.
    ///
    /// The given I/O stream should be an accepted client of this server which
    /// is ready to negotiate the TLS connection.
    pub fn establish<S>(self, stream: S) -> SslStream<S>
        where S: Stream,
    {
        let accept = ssl::SslStream::accept(&self.inner, stream);
        let handshake = Handshake::new(accept);
        let state = State::Handshake(handshake);

        SslStream {
            state: state,
            last_read_err: None,
            last_write_err: None,
        }
    }
}

/*
 *
 * ===== Handshake =====
 *
 */

impl<S: Stream> Handshake<S> {
    fn new(res: Result<ssl::SslStream<S>,
                       ssl::HandshakeError<S>>)
           -> Handshake<S> {
        match res {
            Ok(s) => Handshake::Stream(s),
            Err(ssl::HandshakeError::Failure(e)) => {
                Handshake::Error(io::Error::new(io::ErrorKind::Other, e))
            }
            Err(ssl::HandshakeError::Interrupted(s)) => {
                Handshake::Interrupted(s)
            }
        }
    }

    fn try_complete(&mut self) -> io::Result<Option<ssl::SslStream<S>>> {
        debug!("let's see how the handshake went");

        let mut stream = match mem::replace(self, Handshake::Empty) {
            Handshake::Error(e) => return Err(e),
            Handshake::Empty => panic!("can't poll handshake twice"),
            Handshake::Stream(s) => return Ok(Some(s)),
            Handshake::Interrupted(s) => s,
        };

        debug!("I/O is ready... somewhere");
        match *stream.error() {
            WantRead(_) if stream.get_ref().is_readable() => {}
            WantWrite(_) if stream.get_ref().is_writable() => {}
            WantRead(_) |
            WantWrite(_) => {
                *self = Handshake::Interrupted(stream);
                return Ok(None);
            }
            _ => panic!(), // TODO: handle this
        }

        // TODO: dedup with Handshake::new
        debug!("openssl handshake again");
        match stream.handshake() {
            Ok(s) => Ok(Some(s)),
            Err(ssl::HandshakeError::Failure(e)) => {
                debug!("openssl handshake failure: {:?}", e);
                Err(io::Error::new(io::ErrorKind::Other, e))
            }
            Err(ssl::HandshakeError::Interrupted(s)) => {
                debug!("handshake not completed");
                *self = Handshake::Interrupted(s);
                Ok(None)
            }
        }
    }
}

/*
 *
 * ===== State =====
 *
 */

impl<S: Stream> State<S> {
    fn established(&self) -> Option<&ssl::SslStream<S>> {
        match *self {
            State::Established(ref s) => Some(s),
            _ => None,
        }
    }

    fn established_mut(&mut self) -> Option<&mut ssl::SslStream<S>> {
        match *self {
            State::Established(ref mut s) => Some(s),
            _ => None,
        }
    }
}

fn translate_ssl(err: openssl::error::ErrorStack) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

fn would_block() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "would block")
}

extern crate futures;
extern crate rustls;
extern crate webpki_roots;

use std::fmt;
use std::io::{self, Read, Write, Error, ErrorKind};
use std::mem;
use std::sync::Arc;

use futures::{Async, Poll, Future};
use tokio_core::io::Io;

pub struct ServerContext {
    inner: rustls::ServerConfig,
}

pub struct ClientContext {
    inner: rustls::ClientConfig,
}

impl ServerContext {
    pub fn handshake<S>(self, stream: S) -> ServerHandshake<S>
        where S: Io,
    {
        let config = Arc::new(self.inner);
        let sess = rustls::ServerSession::new(&config);
        ServerHandshake {
            inner: Handshake::Start(TlsStream::new(stream, sess)),
        }
    }
}

impl ClientContext {
    pub fn new() -> io::Result<ClientContext> {
        let mut cx = ClientContext {
            inner: rustls::ClientConfig::new(),
        };
        cx.inner.root_store.add_trust_anchors(&webpki_roots::ROOTS);
        Ok(cx)
    }

    pub fn handshake<S>(self,
                        domain: &str,
                        stream: S) -> ClientHandshake<S>
        where S: Io,
    {
        let config = Arc::new(self.inner);
        let sess = rustls::ClientSession::new(&config, domain);
        ClientHandshake {
            inner: Handshake::Start(TlsStream::new(stream, sess)),
        }
    }
}

pub struct ClientHandshake<S> {
    inner: Handshake<S>,
}

pub struct ServerHandshake<S> {
    inner: Handshake<S>,
}

enum Handshake<T> {
    Start(TlsStream<T>),
    Empty,
}

impl<T> Future for ClientHandshake<T>
    where T: Io,
{
    type Item = TlsStream<T>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<TlsStream<T>, io::Error> {
        self.inner.poll()
    }
}

impl<T> Future for ServerHandshake<T>
    where T: Io,
{
    type Item = TlsStream<T>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<TlsStream<T>, io::Error> {
        self.inner.poll()
    }
}

impl<T> Future for Handshake<T>
    where T: Io,
{
    type Item = TlsStream<T>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<TlsStream<T>, io::Error> {
        loop {
            let s = match *self {
                Handshake::Start(ref s) if !s.session.is_handshaking() => break,
                Handshake::Start(ref mut s) => s,
                Handshake::Empty => panic!("cannot poll twice"),
            };
            debug!("still handshaking");
            match s.do_io() {
                Ok(()) => continue,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
            if !s.session.is_handshaking() {
                break
            }
            return if s.eof {
                Err(io::Error::new(io::ErrorKind::UnexpectedEof,
                                   "unexpected eof during handshake"))
            } else {
                Ok(Async::NotReady)
            }
        }
        debug!("handshake complete");

        match mem::replace(self, Handshake::Empty) {
            Handshake::Start(s) => Ok(s.into()),
            Handshake::Empty => panic!(),
        }
    }
}

pub struct TlsStream<S> {
    inner: S,
    eof: bool,
    session: Box<rustls::Session>,
}

impl<S: Io> TlsStream<S> {
    fn new<T>(stream: S, sess: T) -> TlsStream<S>
        where T: rustls::Session + 'static,
    {
        TlsStream {
            inner: stream,
            eof: false,
            session: Box::new(sess),
        }
    }

    fn do_io(&mut self) -> io::Result<()> {
        debug!("do_io: {:p}", self.session);
        loop {
            if !self.eof &&
               self.session.wants_read() &&
               self.inner.poll_read().is_ready() {
                debug!("reading tls");
                let n = match self.session.read_tls(&mut self.inner) {
                    Ok(n) => n,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        continue
                    }
                    Err(e) => return Err(e),
                };
                if n == 0 {
                    self.eof = true;
                    continue
                }
                debug!("reading packets after {} bytes", n);
                try!(self.session.process_new_packets().map_err(|e| {
                    Error::new(ErrorKind::Other, format!("tls error: {:?}", e))
                }));
                continue
            }
            if self.session.wants_write() && self.inner.poll_write().is_ready() {
                debug!("writing tls");
                match self.session.write_tls(&mut self.inner) {
                    Ok(_n) => continue,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        continue
                    }
                    Err(e) => return Err(e),
                }
            }

            if (!self.eof && self.session.wants_read()) ||
               self.session.wants_write() {
                debug!("read={}, write={}",
                       self.session.wants_read(),
                       self.session.wants_write());
                return Err(io::Error::new(io::ErrorKind::WouldBlock,
                                          "would block"))
            } else {
                debug!("don't want read or write");
                return Ok(())
            }
        }
    }
}

impl<S: Io> Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        debug!("going in for a real read");
        loop {
            match self.session.read(buf) {
                Ok(0) if !self.eof => {}
                other => {
                    debug!("real read: {:?}", other);
                    return other
                }
            }
            try!(self.do_io());
        }
    }
}

impl<S: Io> Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        while self.session.wants_write() && self.inner.poll_write().is_ready() {
            try!(self.session.write_tls(&mut self.inner));
        }
        self.session.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        try!(self.session.flush());
        while self.session.wants_write() && self.inner.poll_write().is_ready() {
            try!(self.session.write_tls(&mut self.inner));
        }
        Ok(())
    }
}

impl<S: Io + fmt::Debug> fmt::Debug for TlsStream<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let wants_read = self.session.wants_read();
        let wants_write = self.session.wants_write();
        let is_handshaking = self.session.is_handshaking();
        fmt.debug_struct("TlsStream")
            .field("inner", &self.inner)
            .field("eof", &self.eof)
            .field("wants_read", &wants_read)
            .field("wants_write", &wants_write)
            .field("is_handshaking", &is_handshaking)
            .finish()
    }
}

impl<S: Io> Io for TlsStream<S> {
    // TODO: more fine-tuned poll_read/poll_write
}

/// Extension trait for servers backed by rustls.
pub trait ServerContextExt: Sized {
    /// Creates a new server context ready to be configured and accept
    /// connections.
    fn new() -> Self;

    /// Returns a shared reference to the underlying `ServerConfig` which will
    /// later be used to initiate this connection.
    fn config(&self) -> &rustls::ServerConfig;

    /// Returns a mutable reference to the underlying `ServerConfig` which will
    /// later be used to initiate this connection.
    fn config_mut(&mut self) -> &mut rustls::ServerConfig;
}

impl ServerContextExt for ::ServerContext {
    fn new() -> ::ServerContext {
        ::ServerContext {
            inner: ServerContext {
                inner: rustls::ServerConfig::new(),
            },
        }
    }

    fn config(&self) -> &rustls::ServerConfig {
        &self.inner.inner
    }

    fn config_mut(&mut self) -> &mut rustls::ServerConfig {
        &mut self.inner.inner
    }
}

/// Extension trait for clients backed by rustls.
pub trait ClientContextExt {
    /// Returns a shared reference to the underlying `ClientConfig` which will
    /// later be used to initiate this connection.
    fn config(&self) -> &rustls::ClientConfig;

    /// Returns a mutable reference to the underlying `ClientConfig` which will
    /// later be used to initiate this connection.
    fn config_mut(&mut self) -> &mut rustls::ClientConfig;
}

impl ClientContextExt for ::ClientContext {
    fn config(&self) -> &rustls::ClientConfig {
        &self.inner.inner
    }

    fn config_mut(&mut self) -> &mut rustls::ClientConfig {
        &mut self.inner.inner
    }
}

/// Extension trait for streams backed by rustls.
pub trait TlsStreamExt {
    /// Returns a shared reference to the underlying TLS session that's being
    /// used.
    ///
    /// Note that interference with the I/O of the session may cause the `Read`
    /// and `Write` impls above to go awry.
    fn session(&self) -> &rustls::Session;

    /// Returns a mutable reference to the underlying TLS session that's being
    /// used.
    ///
    /// Note that interference with the I/O of the session may cause the `Read`
    /// and `Write` impls above to go awry.
    fn session_mut(&mut self) -> &mut rustls::Session;
}

impl<S> TlsStreamExt for ::TlsStream<S> {
    fn session(&self) -> &rustls::Session {
        &*self.inner.session
    }

    fn session_mut(&mut self) -> &mut rustls::Session {
        &mut *self.inner.session
    }
}

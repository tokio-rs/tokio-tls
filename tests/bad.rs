extern crate env_logger;
extern crate futures;
extern crate native_tls;
extern crate tokio;
extern crate tokio_tls;

#[macro_use]
extern crate cfg_if;

use std::io::{self, Error};
use std::net::ToSocketAddrs;

use futures::Future;
use native_tls::TlsConnector;
use tokio::net::TcpStream;
use tokio_tls::TlsConnectorExt;

macro_rules! t {
    ($e:expr) => (match $e {
        Ok(e) => e,
        Err(e) => panic!("{} failed with {:?}", stringify!($e), e),
    })
}

cfg_if! {
    if #[cfg(feature = "force-rustls")] {
        fn verify_failed(err: &Error, s:  &str) {
            let err = err.to_string();
            assert!(err.contains(s), "bad error: {}", err);
        }

        fn assert_expired_error(err: &Error) {
            verify_failed(err, "CertExpired");
        }

        fn assert_wrong_host(err: &Error) {
            verify_failed(err, "CertNotValidForName");
        }

        fn assert_self_signed(err: &Error) {
            verify_failed(err, "UnknownIssuer");
        }

        fn assert_untrusted_root(err: &Error) {
            verify_failed(err, "UnknownIssuer");
        }
    } else if #[cfg(any(feature = "force-openssl",
                        all(not(target_os = "macos"),
                            not(target_os = "windows"),
                            not(target_os = "ios"))))] {
        extern crate openssl;

        use openssl::ssl;
        use native_tls::backend::openssl::ErrorExt;

        fn get(err: &Error) -> &openssl::error::ErrorStack {
            let err = err.get_ref().unwrap();
            match *err.downcast_ref::<native_tls::Error>().unwrap().openssl_error() {
                ssl::Error::Ssl(ref v) => v,
                ref e => panic!("not an ssl eror: {:?}", e),
            }
        }

        fn verify_failed(err: &Error) {
            assert!(get(err).errors().iter().any(|e| {
                e.reason() == Some("certificate verify failed")
            }), "bad errors: {:?}", err);
        }

        use verify_failed as assert_expired_error;
        use verify_failed as assert_wrong_host;
        use verify_failed as assert_self_signed;
        use verify_failed as assert_untrusted_root;
    } else if #[cfg(any(target_os = "macos", target_os = "ios"))] {
        use native_tls::backend::security_framework::ErrorExt;

        fn assert_invalid_cert_chain(err: &Error) {
            let err = err.get_ref().unwrap();
            let err = err.downcast_ref::<native_tls::Error>().unwrap();
            let err = err.security_framework_error();
            assert_eq!(err.message().unwrap(), "The trust policy was not trusted.");
        }

        use assert_invalid_cert_chain as assert_expired_error;
        use assert_invalid_cert_chain as assert_wrong_host;
        use assert_invalid_cert_chain as assert_self_signed;
        use assert_invalid_cert_chain as assert_untrusted_root;
    } else {
        extern crate winapi;

        use native_tls::backend::schannel::ErrorExt;
        use winapi::shared::winerror::*;

        fn assert_expired_error(err: &Error) {
            let err = err.get_ref().unwrap();
            let err = err.downcast_ref::<native_tls::Error>().unwrap();
            let err = err.schannel_error();
            let code = err.raw_os_error().unwrap();
            assert_eq!(code as usize, CERT_E_EXPIRED as usize);
        }

        fn assert_wrong_host(err: &Error) {
            let err = err.get_ref().unwrap();
            let err = err.downcast_ref::<native_tls::Error>().unwrap();
            let err = err.schannel_error();
            let code = err.raw_os_error().unwrap() as usize;
            // TODO: this... may be a bug in schannel-rs
            assert!(code == CERT_E_CN_NO_MATCH as usize ||
                    code == SEC_E_MESSAGE_ALTERED as usize,
                    "bad error code: {:x}", code);
        }

        fn assert_self_signed(err: &Error) {
            let err = err.get_ref().unwrap();
            let err = err.downcast_ref::<native_tls::Error>().unwrap();
            let err = err.schannel_error();
            let code = err.raw_os_error().unwrap();
            assert_eq!(code as usize, CERT_E_UNTRUSTEDROOT as usize);
        }

        fn assert_untrusted_root(err: &Error) {
            let err = err.get_ref().unwrap();
            let err = err.downcast_ref::<native_tls::Error>().unwrap();
            let err = err.schannel_error();
            let code = err.raw_os_error().unwrap();
            assert_eq!(code as usize, CERT_E_UNTRUSTEDROOT as usize);
        }
    }
}

fn get_host(host: &'static str) -> Box<Future<Item = (), Error = Error> + Send> {
    drop(env_logger::init());

    let addr = format!("{}:443", host);
    let addr = t!(addr.to_socket_addrs()).next().unwrap();

    let client = TcpStream::connect(&addr);
    let data = client.and_then(move |socket| {
        let builder = t!(TlsConnector::builder());
        let cx = t!(builder.build());
        cx.connect_async(host, socket).map_err(|e| {
            Error::new(io::ErrorKind::Other, e)
        })
    });

    Box::new(
        data
            .then(|res| {
                assert!(res.is_err());
                Err(res.err().unwrap())
            })
    )
}

#[test]
fn expired() {
    tokio::run(
        get_host("expired.badssl.com")
            .then(|res| {
                assert_expired_error(&res.err().unwrap());
                Ok(())
            })
    );
}

// TODO: the OSX builders on Travis apparently fail this tests spuriously?
//       passes locally though? Seems... bad!
#[test]
#[cfg_attr(all(target_os = "macos", feature = "force-openssl"), ignore)]
fn wrong_host() {
    tokio::run(
        get_host("wrong.host.badssl.com")
            .then(|res| {
                assert_wrong_host(&res.err().unwrap());
                Ok(())
            })
    );
}

#[test]
fn self_signed() {
    tokio::run(
        get_host("self-signed.badssl.com")
            .then(|res| {
                assert_self_signed(&res.err().unwrap());
                Ok(())
            })
    );
}

#[test]
fn untrusted_root() {
    tokio::run(
        get_host("untrusted-root.badssl.com")
            .then(|res| {
                assert_untrusted_root(&res.err().unwrap());
                Ok(())
            })
    );
}

extern crate env_logger;
extern crate futures;
extern crate native_tls;
extern crate tokio_core;
extern crate tokio_tls;

#[macro_use]
extern crate cfg_if;

use std::io::{self, Error};
use std::net::ToSocketAddrs;

use futures::Future;
use native_tls::TlsConnector;
use tokio_core::net::TcpStream;
use tokio_core::reactor::Core;
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

        fn verify_failed(err: &Error) {
            assert!(format!("{}", err).contains("certificate verify failed"))
        }

        use verify_failed as assert_expired_error;
        use verify_failed as assert_wrong_host;
        use verify_failed as assert_self_signed;
        use verify_failed as assert_untrusted_root;
    } else if #[cfg(any(target_os = "macos", target_os = "ios"))] {

        fn assert_invalid_cert_chain(err: &Error) {
            assert!(format!("{}", err).contains("The trust policy was not trusted."))
        }

        use assert_invalid_cert_chain as assert_expired_error;
        use assert_invalid_cert_chain as assert_wrong_host;
        use assert_invalid_cert_chain as assert_self_signed;
        use assert_invalid_cert_chain as assert_untrusted_root;
    } else {
        extern crate winapi;

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

fn get_host(host: &'static str) -> Error {
    drop(env_logger::init());

    let addr = format!("{}:443", host);
    let addr = t!(addr.to_socket_addrs()).next().unwrap();

    let mut l = t!(Core::new());
    let client = TcpStream::connect(&addr, &l.handle());
    let data = client.and_then(move |socket| {
        let builder = TlsConnector::builder();
        let cx = builder.build().unwrap();
        cx.connect_async(host, socket).map_err(|e| {
            Error::new(io::ErrorKind::Other, e)
        })
    });

    let res = l.run(data);
    assert!(res.is_err());
    res.err().unwrap()
}

#[test]
fn expired() {
    assert_expired_error(&get_host("expired.badssl.com"))
}

// TODO: the OSX builders on Travis apparently fail this tests spuriously?
//       passes locally though? Seems... bad!
#[test]
#[cfg_attr(all(target_os = "macos", feature = "force-openssl"), ignore)]
fn wrong_host() {
    assert_wrong_host(&get_host("wrong.host.badssl.com"))
}

#[test]
fn self_signed() {
    assert_self_signed(&get_host("self-signed.badssl.com"))
}

#[test]
fn untrusted_root() {
    assert_untrusted_root(&get_host("untrusted-root.badssl.com"))
}

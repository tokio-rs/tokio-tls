# tokio-tls

An implementation of TLS/SSL streams for Tokio

[![Build Status](https://travis-ci.org/tokio-rs/tokio-tls.svg?branch=master)](https://travis-ci.org/alexcrichton/tokio-tls)
[![Build status](https://ci.appveyor.com/api/projects/status/iiut5d2mts6bt5g1?svg=true)](https://ci.appveyor.com/project/alexcrichton/tokio-tls)

[Documentation](http://tokio-rs.com/tokio-tls/futures_tls)

## Usage

First, add this to your `Cargo.toml`:

```toml
[dependencies]
futures-tls = { git = "https://github.com/tokio-rs/tokio-tls" }
```

Next, add this to your crate:

```rust
extern crate futures_tls;
```

# License

`tokio-tls` is primarily distributed under the terms of both the MIT license
and the Apache License (Version 2.0), with portions covered by various BSD-like
licenses.

See LICENSE-APACHE, and LICENSE-MIT for details.


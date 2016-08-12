# Tokio SSL

An implementation of TLS/SSL streams for use with
[Tokio](https://github.com/tokio-rs/tokio).

**This library is still very experimental**

## Usage

First, add this to your `Cargo.toml`:

```toml
[dependencies]
tokio-tls = { git = "https://github.com/tokio-rs/tokio-ssl" }
```

Next, add this to your crate:

```rust
extern crate tokio_ssl;
```

# License

`futures-tls` is primarily distributed under the terms of both the MIT license
and the Apache License (Version 2.0), with portions covered by various BSD-like
licenses.

See LICENSE-APACHE, and LICENSE-MIT for details.

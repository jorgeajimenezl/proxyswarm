# Proxyswarm
[![Rust](https://github.com/jorgeajimenezl/proxyswarm/actions/workflows/rust.yml/badge.svg)](https://github.com/jorgeajimenezl/proxyswarm/actions/workflows/rust.yml)
![GitHub tag](https://img.shields.io/github/v/tag/jorgeajimenezl/proxyswarm)

Proxyswarm is a lightweight proxy that allows redirect HTTP(S) traffic through a proxy.

WARNING: This app isn't recomended for download large files, for these things use apps like [curl](#how-download-a-file-with-curl-using-proxy), wget or other download programs. For web browse use standard web browser like Chromium and Firefox, these apps and others have good proxy support. **USE THIS APP WITH PROGRAMS WITHOUT PROXY SUPPORT LIKE STEAM, PIP, ETC**

## Features
- **High performace** (builting using tokio.rs)
- **Multiple connections** at same time

## Authentication schemes supported
- Basic
- Digest ([RFC 2069](https://tools.ietf.org/html/rfc2069), [RFC 2617](https://tools.ietf.org/html/rfc2617))

## Compilation
```shell
$ git clone https://github.com/jorgeajimenezl/proxyswarm.git
$ cd proxyswarm
$ cargo build --release
```

Now you can get build from `target/release/proxyswarm` directory.

## Getting start
For start only run the proxyswarm (optional: run config file test first)
```shell
$ proxyswarm -t
$ proxyswarm
```

If you use `systemd` you can start proxyswarm service
```shell
$ systemctl start proxyswarm.service
```

## FAQ
### Superuser?
No, isn't necessary for proxyswarm.

### How download a file with curl using proxy?
First you must have installed [curl](https://github.com/curl), after launch a console and type
```shell
$ curl --proxy [http|https|sock]://host:port --proxy-user user:pass --proxy-anyauth
```

## Author
This program was deverloped by Jorge Alejandro Jiménez Luna <<jorgeajimenezl17@gmail.com>>

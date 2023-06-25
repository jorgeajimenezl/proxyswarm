# Proxyswarm

[![Rust](https://github.com/jorgeajimenezl/proxyswarm/actions/workflows/rust.yml/badge.svg)](https://github.com/jorgeajimenezl/proxyswarm/actions/workflows/rust.yml)
![GitHub tag](https://img.shields.io/github/v/tag/jorgeajimenezl/proxyswarm)
![AUR version](https://img.shields.io/aur/version/proxyswarm)

Proxyswarm is a tiny lightweight proxy that allows redirect HTTP[S] traffic through a proxy.

## Features

- **High performace** (built using `tokio.rs`)
- **Multiple connections** at same time
- **HTTP[S] Proxy**

## Authentication schemes supported

- Basic
- Digest ([RFC 2069](https://tools.ietf.org/html/rfc2069), [RFC 2617](https://tools.ietf.org/html/rfc2617))

## Build

```shell
git clone https://github.com/jorgeajimenezl/proxyswarm.git
cd proxyswarm
cargo build --release
```

Now you can get build from `target/release/proxyswarm` directory.

## Getting start

For start only run the proxyswarm:

```shell
proxyswarm
```

If you use `systemd` you can start proxyswarm service

```shell
systemctl start proxyswarm.service
```

## FAQ

### Superuser?

No, isn't necessary for proxyswarm.

### How download a file with curl using proxy?

First you must have installed [curl](https://github.com/curl), after launch a console and type

```shell
curl --proxy [http|https|sock]://host:port --proxy-user user:pass --proxy-anyauth
```

## Author

This program was deverloped by Jorge Alejandro Jiménez Luna <<jorgeajimenezl17@gmail.com>>

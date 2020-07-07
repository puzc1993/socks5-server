# A simple SOCKS5 server in RUST.

## usage:
```
socks5_server [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -a, --address <ADDR>    listen address
    -p, --port <PORT>       listen port

```

## dependencies
* tokio
* anyhow
* bytes
* clap

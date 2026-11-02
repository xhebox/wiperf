# wiperf

[![Test](https://github.com/xhebox/wiperf/actions/workflows/test.yml/badge.svg)](https://github.com/xhebox/wiperf/actions/workflows/test.yml)
[![crates.io](https://img.shields.io/crates/v/wiperf.svg)](https://crates.io/crates/wiperf)
[![docs.rs](https://img.shields.io/docsrs/wiperf)](https://docs.rs/wiperf)
[![License: MIT](https://img.shields.io/crates/l/wiperf.svg)](https://github.com/xhebox/wiperf/blob/main/LICENSE)

Throughput benchmark tool and library speaking the iperf3 wire protocol over TCP, UDP, Unix domain sockets, and Linux `AF_VSOCK`.

## Install

```
cargo binstall wiperf
```

Prebuilt binaries come from the GitHub releases; `cargo install wiperf` builds from source.

## Usage

```
wiperf (-s | -c <host> | --unix <path>) [--vsock] [-p <port>] [-t <sec>] [-O <sec>] [-P <streams>] [-l <bytes>] [-u] [-b <bps>] [-R] [-1] [-J]
```

```console
$ wiperf -s -p 5201
$ wiperf -c 127.0.0.1 -t 10 -P 4 -l 65536
$ wiperf -c 127.0.0.1 -R -t 10
$ wiperf -c 127.0.0.1 -u -b 100000000 -t 5
```

Unix domain sockets and Linux `AF_VSOCK` use the same flags; with `--vsock`, `-c` takes the destination CID:

```console
$ wiperf -s --unix /tmp/wiperf.sock
$ wiperf --unix /tmp/wiperf.sock -t 5

$ wiperf -s --vsock -p 5201
$ wiperf -c 2 --vsock -p 5201 -t 5
```

`-R` reverses direction (server sends, client receives). `-O` omits a leading warm-up from the `-t` duration (for example, `-t 10 -O 2` reports the last 8 seconds). `-1` exits the server after one test, and `-J` prints a one-line JSON summary.

`--udp` runs over IP only and cannot be combined with `--unix` or `--vsock`. `--vsock` is available on Linux only.

## Using as a library

```rust,no_run
use wiperf::{TestParams, connect_tcp, run_stream_client};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let params = TestParams {
        time: Some(5),
        parallel: Some(2),
        ..Default::default()
    };
    let report = completion::block_on(run_stream_client(&params, || {
        connect_tcp("127.0.0.1:5201".parse().unwrap())
    }))??;
    println!("{} streams", report.streams.len());
    Ok(())
}
```

`run_stream_client` and `serve_stream_once` take caller-supplied connect and accept closures over any `StreamIo` transport, so benchmarks can run over custom tunnels or multiplexed channels as well as the built-in TCP, Unix, and vsock helpers.

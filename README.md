# gpgpdump - OpenPGP packet visualizer

[![Build Status](https://travis-ci.org/spiegel-im-spiegel/gpgpdump.svg?branch=master)](https://travis-ci.org/spiegel-im-spiegel/gpgpdump)
[![GitHub license](https://img.shields.io/badge/license-Apache%202-blue.svg)](https://raw.githubusercontent.com/spiegel-im-spiegel/gpgpdump/master/LICENSE)

[gpgpdump](https://github.com/spiegel-im-spiegel/gpgpdump) is a OpenPGP ([RFC 4880](https://tools.ietf.org/html/rfc4880)) packet visualizer by [golang](https://golang.org/).

- Adapted from [pgpdump](https://github.com/kazu-yamamoto/pgpdump)
- Output with [TOML](https://github.com/toml-lang/toml) (or [JSON](https://tools.ietf.org/html/rfc7159)) format
- Support [RFC 5581](http://tools.ietf.org/html/rfc5581)
- Support [RFC 6637](http://tools.ietf.org/html/rfc6637)

## Dependencies

- [`github.com/spiegel-im-spiegel/gocli`](https://github.com/spiegel-im-spiegel/gocli)
- [`github.com/BurntSushi/toml`](https://github.com/BurntSushi/toml)
- [`golang.org/x/crypto/openpgp/armor`](https://godoc.org/golang.org/x/crypto/openpgp/armor)
- [`golang.org/x/crypto/openpgp/packet`](https://godoc.org/golang.org/x/crypto/openpgp/packet)

## Install

```
$ go get -v github.com/spiegel-im-spiegel/gpgpdump
```

## Usage

```
$ gpgpdump -h
USAGE:
   gpgpdump [options] [OpenPGP file]

OPTIONS:
   -h -- output this help
   -v -- output version
   -a -- accepts ASCII input only
   -i -- dumps multi-precision integers
   -j -- output with JSON format
   -l -- dumps literal packets (tag 11)
   -m -- dumps marker packets (tag 10)
   -p -- dumps private packets (tag 60-63)
   -u -- output UTC time
```

## License

Copyright 2016 Spiegel.
Licensed under [Apache License Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

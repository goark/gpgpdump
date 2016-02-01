# gpgpdump - OpenPGP packet visualizer

[![GitHub license](https://img.shields.io/badge/license-Apache%202-blue.svg)](https://raw.githubusercontent.com/spiegel-im-spiegel/gpgpdump/master/LICENSE)

[gpgpdump](https://github.com/spiegel-im-spiegel/gpgpdump) is a OpenPGP packet ([RFC 4880](https://tools.ietf.org/html/rfc4880)).

- [pgpdump](https://github.com/kazu-yamamoto/pgpdump) compatible (maybe)
- Support [RFC 5581](http://tools.ietf.org/html/rfc5581)
- Support [RFC 6637](http://tools.ietf.org/html/rfc6637)

## Dependencies

- [`github.com/spiegel-im-spiegel/gocli`](https://github.com/spiegel-im-spiegel/gocli)
- `golang.org/x/crypto/openpgp/`[`armor`](https://godoc.org/golang.org/x/crypto/openpgp/armor)
- `golang.org/x/crypto/openpgp/`[`packet`](https://godoc.org/golang.org/x/crypto/openpgp/packet)

## Install

```
$ go get -v github.com/spiegel-im-spiegel/gpgpdump
```

## Usage

```
$ gpgpdump -h
USAGE:
   gpgpdump [options] [PGPfile]

OPTIONS:
   -h -- displays this help
   -v -- displays version
   -a -- accepts ASCII input only
   -g -- selects alternate dump format
   -i -- dumps integer packets
   -l -- dumps literal packets
   -m -- dumps marker packets
   -p -- dumps private packets
   -u -- displays UTC time
```

## License

Copyright 2016 Spiegel.
Licensed under [Apache License Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

# gpgpdump - OpenPGP packet visualizer

[![Build Status](https://travis-ci.org/spiegel-im-spiegel/gpgpdump.svg?branch=master)](https://travis-ci.org/spiegel-im-spiegel/gpgpdump)
[![GitHub license](https://img.shields.io/badge/license-Apache%202-blue.svg)](https://raw.githubusercontent.com/spiegel-im-spiegel/gpgpdump/master/LICENSE)
[![GitHub release](http://img.shields.io/github/release/spiegel-im-spiegel/gpgpdump.svg)](https://github.com/spiegel-im-spiegel/gpgpdump/releases/latest)

[gpgpdump](https://github.com/spiegel-im-spiegel/gpgpdump) is a OpenPGP ([RFC 4880](https://tools.ietf.org/html/rfc4880)) packet visualizer by [golang](https://golang.org/).

- Based on [pgpdump](https://github.com/kazu-yamamoto/pgpdump)
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

### Binaries

See [latest release](https://github.com/spiegel-im-spiegel/gpgpdump/releases/latest).

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

$ cat sig
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v2

iF4EARMIAAYFAlTDCN8ACgkQMfv9qV+7+hg2HwEA6h2iFFuCBv3VrsSf2BREQaT1
T1ZprZqwRPOjiLJg9AwA/ArTwCPz7c2vmxlv7sRlRLUI6CdsOqhuO1KfYXrq7idI
=ZOTN
-----END PGP SIGNATURE-----

$ cat sig | gpgpdump
[[Packet]]
  name = "Packet"
  value = "Signature Packet (tag 2)"
  note = "94 bytes"

  [[Packet.Item]]
    name = "Version"
    value = "4"
    dump = "04"
    note = "new"

  [[Packet.Item]]
    name = "Signiture Type"
    value = "Signature of a canonical text document (0x01)"

  [[Packet.Item]]
    name = "Public-key Algorithm"
    value = "ECDSA public key algorithm (pub 19)"

  [[Packet.Item]]
    name = "Hash Algorithm"
    value = "SHA256 (hash 8)"

  [[Packet.Item]]
    name = "Hashed Subpacket"

    [[Packet.Item.Item]]
      name = "Signature Creation Time (sub 2)"
      value = "2015-01-24T11:52:15+09:00"
      dump = "54 c3 08 df"

  [[Packet.Item]]
    name = "Unhashed Subpacket"

    [[Packet.Item.Item]]
      name = "Issuer (sub 16)"
      value = "0x31FBFDA95FBBFA18"

  [[Packet.Item]]
    name = "Hash left 2 bytes"
    dump = "36 1f"

  [[Packet.Item]]
    name = "Multi-precision integer"
    dump = "..."
    note = "ECDSA r (256 bits)"

  [[Packet.Item]]
    name = "Multi-precision integer"
    dump = "..."
    note = "ECDSA s (252 bits)"

$ cat sig | gpgpdump -j
{
  "Packet": [
    {
      "name": "Packet",
      "value": "Signature Packet (tag 2)",
      "note": "94 bytes",
      "Item": [
        {
          "name": "Version",
          "value": "4",
          "dump": "04",
          "note": "new"
        },
        {
          "name": "Signiture Type",
          "value": "Signature of a canonical text document (0x01)"
        },
        {
          "name": "Public-key Algorithm",
          "value": "ECDSA public key algorithm (pub 19)"
        },
        {
          "name": "Hash Algorithm",
          "value": "SHA256 (hash 8)"
        },
        {
          "name": "Hashed Subpacket",
          "Item": [
            {
              "name": "Signature Creation Time (sub 2)",
              "value": "2015-01-24T11:52:15+09:00",
              "dump": "54 c3 08 df"
            }
          ]
        },
        {
          "name": "Unhashed Subpacket",
          "Item": [
            {
              "name": "Issuer (sub 16)",
              "value": "0x31FBFDA95FBBFA18"
            }
          ]
        },
        {
          "name": "Hash left 2 bytes",
          "dump": "36 1f"
        },
        {
          "name": "Multi-precision integer",
          "dump": "...",
          "note": "ECDSA r (256 bits)"
        },
        {
          "name": "Multi-precision integer",
          "dump": "...",
          "note": "ECDSA s (252 bits)"
        }
      ]
    }
  ]
}
```

## License

Copyright 2016 Spiegel.
Licensed under [Apache License Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

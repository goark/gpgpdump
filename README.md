# gpgpdump - OpenPGP packet visualizer

[![Build Status](https://travis-ci.org/spiegel-im-spiegel/gpgpdump.svg?branch=master)](https://travis-ci.org/spiegel-im-spiegel/gpgpdump)
[![GitHub license](https://img.shields.io/badge/license-Apache%202-blue.svg)](https://raw.githubusercontent.com/spiegel-im-spiegel/gpgpdump/master/LICENSE)
[![GitHub release](http://img.shields.io/github/release/spiegel-im-spiegel/gpgpdump.svg)](https://github.com/spiegel-im-spiegel/gpgpdump/releases/latest)

[gpgpdump](https://github.com/spiegel-im-spiegel/gpgpdump) is a OpenPGP ([RFC 4880](https://tools.ietf.org/html/rfc4880)) packet visualizer by [golang](https://golang.org/).

- Based on [pgpdump](https://github.com/kazu-yamamoto/pgpdump)
- Provide [golang](https://golang.org/) package and command-line Interface
- Output with [TOML](https://github.com/toml-lang/toml) (or [JSON](https://tools.ietf.org/html/rfc7159)) format
- Support [RFC 5581](http://tools.ietf.org/html/rfc5581) and [RFC 6637](http://tools.ietf.org/html/rfc6637)

## Install

```
$ go get -v github.com/spiegel-im-spiegel/gpgpdump
```

Installing by [dep].

```
$ dep ensure -add github.com/spiegel-im-spiegel/godump
```

### Usage

```go
const openpgpStr = `
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v2

iF4EARMIAAYFAlTDCN8ACgkQMfv9qV+7+hg2HwEA6h2iFFuCBv3VrsSf2BREQaT1
T1ZprZqwRPOjiLJg9AwA/ArTwCPz7c2vmxlv7sRlRLUI6CdsOqhuO1KfYXrq7idI
=ZOTN
-----END PGP SIGNATURE-----
`

info, err := gpgpdump.Parse(strings.NewReader(openpgpStr), options.NewOptions())
if err != nil {
	return
}
fmt.Println(info.Packets[0].Value)
// Output:
// Signature Packet (tag 2)

```

## Command-Line Interface

### Binaries

See [latest release](https://github.com/spiegel-im-spiegel/gpgpdump/releases/latest).

### Usage

```
$ gpgpdump -h
Usage:
  gpgpdump [flags] [PGPfile]

Flags:
  -a, --armor     accepts ASCII input only
  -h, --help      help for gpgpdump
  -i, --int       dumps multi-precision integers
  -j, --json      output with JSON format
  -l, --literal   dumps literal packets (tag 11)
  -m, --marker    dumps marker packets (tag 10)
  -p, --private   dumps private packets (tag 60-63)
  -u, --utc       output with UTC time
  -v, --version   output version of gpgpdump

$ cat sig
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v2

iF4EARMIAAYFAlTDCN8ACgkQMfv9qV+7+hg2HwEA6h2iFFuCBv3VrsSf2BREQaT1
T1ZprZqwRPOjiLJg9AwA/ArTwCPz7c2vmxlv7sRlRLUI6CdsOqhuO1KfYXrq7idI
=ZOTN
-----END PGP SIGNATURE-----

$ cat sig | gpgpdump -u
[[Packet]]
  name = "Packet"
  value = "Signature Packet (tag 2)"
  note = "94 bytes"

  [[Packet.Item]]
    name = "Version"
    value = "4"
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
    note = "6 bytes"

    [[Packet.Item.Item]]
      name = "Signature Creation Time (sub 2)"
      value = "2015-01-24T02:52:15Z"

  [[Packet.Item]]
    name = "Unhashed Subpacket"
    note = "10 bytes"

    [[Packet.Item.Item]]
      name = "Issuer (sub 16)"
      value = "0x31fbfda95fbbfa18"

  [[Packet.Item]]
    name = "Hash left 2 bytes"
    dump = "36 1f"

  [[Packet.Item]]
    name = "Multi-precision integer"
    note = "ECDSA r (256 bits)"

  [[Packet.Item]]
    name = "Multi-precision integer"
    note = "ECDSA s (252 bits)"

$ cat sig | gpgpdump -j -u
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
          "note": "6 bytes",
          "Item": [
            {
              "name": "Signature Creation Time (sub 2)",
              "value": "2015-01-24T02:52:15Z"
            }
          ]
        },
        {
          "name": "Unhashed Subpacket",
          "note": "10 bytes",
          "Item": [
            {
              "name": "Issuer (sub 16)",
              "value": "0x31fbfda95fbbfa18"
            }
          ]
        },
        {
          "name": "Hash left 2 bytes",
          "dump": "36 1f"
        },
        {
          "name": "Multi-precision integer",
          "note": "ECDSA r (256 bits)"
        },
        {
          "name": "Multi-precision integer",
          "note": "ECDSA s (252 bits)"
        }
      ]
    }
  ]
}
```

## Dependencies

```
dep status -dot | dot -Tpng -o dependency.png
```

[![Dependencies](dependency.png)](dependency.png)

[gpgpdump]: https://github.com/spiegel-im-spiegel/gpgpdump "spiegel-im-spiegel/gpgpdump: gpgpdump - OpenPGP packet visualizer"
[dep]: https://github.com/golang/dep "golang/dep: Go dependency management tool"

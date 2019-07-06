# [gpgpdump] - OpenPGP packet visualizer

[![Build Status](https://travis-ci.org/spiegel-im-spiegel/gpgpdump.svg?branch=master)](https://travis-ci.org/spiegel-im-spiegel/gpgpdump)
[![GitHub license](https://img.shields.io/badge/license-Apache%202-blue.svg)](https://raw.githubusercontent.com/spiegel-im-spiegel/gpgpdump/master/LICENSE)
[![GitHub release](http://img.shields.io/github/release/spiegel-im-spiegel/gpgpdump.svg)](https://github.com/spiegel-im-spiegel/gpgpdump/releases/latest)

[gpgpdump] is a OpenPGP ([RFC 4880]) packet visualizer by [golang](https://golang.org/).

- Based on [pgpdump](https://github.com/kazu-yamamoto/pgpdump)
- Provide [golang](https://golang.org/) package and command-line Interface
- Output with plain text, [TOML](https://github.com/toml-lang/toml), and [JSON](https://tools.ietf.org/html/rfc7159) format
- Support [RFC 5581] and [RFC 6637]
- Support a part of [RFC 4880bis]

## Declare [gpgpdump] module

See [go.mod](https://github.com/spiegel-im-spiegel/gpgpdump/blob/master/go.mod) file. 

## Usage of [gpgpdump] package

```go
import (
	"fmt"
	"strings"

	"github.com/spiegel-im-spiegel/gpgpdump"
	"github.com/spiegel-im-spiegel/gpgpdump/options"
)

const openpgpStr = `
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v2

iF4EARMIAAYFAlTDCN8ACgkQMfv9qV+7+hg2HwEA6h2iFFuCBv3VrsSf2BREQaT1
T1ZprZqwRPOjiLJg9AwA/ArTwCPz7c2vmxlv7sRlRLUI6CdsOqhuO1KfYXrq7idI
=ZOTN
-----END PGP SIGNATURE-----
`

info, err := gpgpdump.Parse(
    strings.NewReader(openpgpStr),
    options.New(
        options.Set(options.ARMOR, true),
        options.Set(options.UTC, true),
    )
)
if err != nil {
	return
}
fmt.Println(info.Packets[0].Name)
// Output:
// Signature Packet (tag 2)
```

## Command-Line Interface

### Download and Build

```
$ go get github.com/spiegel-im-spiegel/gpgpdump@latest
```

### Binaries

See [latest release](https://github.com/spiegel-im-spiegel/gpgpdump/releases/latest).

### Usage

```
$ gpgpdump -h
Usage:
  gpgpdump [flags]
  gpgpdump [command]

Available Commands:
  help        Help about any command
  hkp         Dumps from OpenPGP key server
  version     Print the version number

Flags:
  -a, --armor         accepts ASCII input only
      --debug         for debug
  -f, --file string   path of OpenPGP file
  -h, --help          help for gpgpdump
      --indent int    indent size for output string
  -i, --int           dumps multi-precision integers
  -j, --json          output with JSON format
  -l, --literal       dumps literal packets (tag 11)
  -m, --marker        dumps marker packets (tag 10)
  -p, --private       dumps private packets (tag 60-63)
  -t, --toml          output with TOML format
  -u, --utc           output with UTC time
  -v, --version       output version of gpgpdump

Use "gpgpdump [command] --help" for more information about a command.

$ cat sig
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v2

iF4EARMIAAYFAlTDCN8ACgkQMfv9qV+7+hg2HwEA6h2iFFuCBv3VrsSf2BREQaT1
T1ZprZqwRPOjiLJg9AwA/ArTwCPz7c2vmxlv7sRlRLUI6CdsOqhuO1KfYXrq7idI
=ZOTN
-----END PGP SIGNATURE-----

$ cat sig | gpgpdump -u --indent 2
Signature Packet (tag 2) (94 bytes)
  Version: 4 (current)
  Signiture Type: Signature of a canonical text document (0x01)
  Public-key Algorithm: ECDSA public key algorithm (pub 19)
  Hash Algorithm: SHA2-256 (hash 8)
  Hashed Subpacket (6 bytes)
    Signature Creation Time (sub 2): 2015-01-24T02:52:15Z
  Unhashed Subpacket (10 bytes)
    Issuer (sub 16): 0x31fbfda95fbbfa18
  Hash left 2 bytes
    36 1f
  ECDSA value r (256 bits)
  ECDSA value s (252 bits)

$ cat sig | gpgpdump -t -u
[[Packet]]
  name = "Signature Packet (tag 2)"
  note = "94 bytes"

  [[Packet.Item]]
    name = "Version"
    value = "4"
    note = "current"

  [[Packet.Item]]
    name = "Signiture Type"
    value = "Signature of a canonical text document (0x01)"

  [[Packet.Item]]
    name = "Public-key Algorithm"
    value = "ECDSA public key algorithm (pub 19)"

  [[Packet.Item]]
    name = "Hash Algorithm"
    value = "SHA2-256 (hash 8)"

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
    name = "ECDSA value r"
    note = "256 bits"

  [[Packet.Item]]
    name = "ECDSA value s"
    note = "252 bits"

$ cat sig | gpgpdump -j -u --indent 2
{
  "Packet": [
    {
      "name": "Signature Packet (tag 2)",
      "note": "94 bytes",
      "Item": [
        {
          "name": "Version",
          "value": "4",
          "note": "current"
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
          "value": "SHA2-256 (hash 8)"
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
          "name": "ECDSA value r",
          "note": "256 bits"
        },
        {
          "name": "ECDSA value s",
          "note": "252 bits"
        }
      ]
    }
  ]
}
```

### HKP Access Mode

```
$ gpgpdump hkp -h
Dumps from OpenPGP key server

Usage:
  gpgpdump hkp [flags] <user id>

Flags:
  -h, --help               help for hkp
      --keyserver string   OpenPGP key server (default "keys.gnupg.net")
      --port int           port number of OpenPGP key server (default 11371)
      --proxy string       URL of proxy server
      --raw                output raw text from OpenPGP key server
      --secure             enable HKP over HTTPS

Global Flags:
  -a, --armor        accepts ASCII input only
      --debug        for debug
      --indent int   indent size for output string
  -i, --int          dumps multi-precision integers
  -j, --json         output with JSON format
  -l, --literal      dumps literal packets (tag 11)
  -m, --marker       dumps marker packets (tag 10)
  -p, --private      dumps private packets (tag 60-63)
  -t, --toml         output with TOML format
  -u, --utc          output with UTC time

$ gpgpdump hkp -u --indent 2 0x44ce6900e2b307a4
Public-Key Packet (tag 6) (269 bytes)
  Version: 4 (current)
  Public key creation time: 2009-11-08T15:20:55Z
    4a f6 e1 d7
  Public-key Algorithm: RSA (Encrypt or Sign) (pub 1)
  RSA public modulus n (2048 bits)
  RSA public encryption exponent e (17 bits)
User ID Packet (tag 13) (25 bytes)
  User ID: Alice <alice@example.com>
Signature Packet (tag 2) (312 bytes)
  Version: 4 (current)
  Signiture Type: Positive certification of a User ID and Public-Key packet (0x13)
  Public-key Algorithm: RSA (Encrypt or Sign) (pub 1)
  Hash Algorithm: SHA-1 (hash 2)
  Hashed Subpacket (34 bytes)
    Signature Creation Time (sub 2): 2009-11-08T15:20:55Z
    Key Flags (sub 27) (1 bytes)
      Flag: This key may be used to certify other keys.
      Flag: This key may be used to sign data.
    Preferred Symmetric Algorithms (sub 11) (5 bytes)
      Symmetric Algorithm: AES with 256-bit key (sym 9)
      Symmetric Algorithm: AES with 192-bit key (sym 8)
      Symmetric Algorithm: AES with 128-bit key (sym 7)
      Symmetric Algorithm: CAST5 (128 bit key, as per) (sym 3)
      Symmetric Algorithm: TripleDES (168 bit key derived from 192) (sym 2)
    Preferred Hash Algorithms (sub 21) (5 bytes)
      Hash Algorithm: SHA2-256 (hash 8)
      Hash Algorithm: SHA-1 (hash 2)
      Hash Algorithm: SHA2-384 (hash 9)
      Hash Algorithm: SHA2-512 (hash 10)
      Hash Algorithm: SHA2-224 (hash 11)
    Preferred Compression Algorithms (sub 22) (3 bytes)
      Compression Algorithm: ZLIB <RFC1950> (comp 2)
      Compression Algorithm: BZip2 (comp 3)
      Compression Algorithm: ZIP <RFC1951> (comp 1)
    Features (sub 30) (1 bytes)
      Flag: Modification Detection (packets 18 and 19)
    Key Server Preferences (sub 23) (1 bytes)
      Flag: No-modify
  Unhashed Subpacket (10 bytes)
    Issuer (sub 16): 0x44ce6900e2b307a4
  Hash left 2 bytes
    93 62
  RSA signature value m^d mod n (2045 bits)
Public-Subkey Packet (tag 14) (269 bytes)
  Version: 4 (current)
  Public key creation time: 2009-11-08T15:20:55Z
    4a f6 e1 d7
  Public-key Algorithm: RSA (Encrypt or Sign) (pub 1)
  RSA public modulus n (2048 bits)
  RSA public encryption exponent e (17 bits)
Signature Packet (tag 2) (287 bytes)
  Version: 4 (current)
  Signiture Type: Subkey Binding Signature (0x18)
  Public-key Algorithm: RSA (Encrypt or Sign) (pub 1)
  Hash Algorithm: SHA-1 (hash 2)
  Hashed Subpacket (9 bytes)
    Signature Creation Time (sub 2): 2009-11-08T15:20:55Z
    Key Flags (sub 27) (1 bytes)
      Flag: This key may be used to encrypt communications.
      Flag: This key may be used to encrypt storage.
  Unhashed Subpacket (10 bytes)
    Issuer (sub 16): 0x44ce6900e2b307a4
  Hash left 2 bytes
    66 f3
  RSA signature value m^d mod n (2048 bits)
```

[gpgpdump]: https://github.com/spiegel-im-spiegel/gpgpdump "spiegel-im-spiegel/gpgpdump: gpgpdump - OpenPGP packet visualizer"
[RFC 4880]: https://tools.ietf.org/html/rfc4880
[RFC 4880bis]: https://datatracker.ietf.org/doc/draft-ietf-openpgp-rfc4880bis/
[RFC 5581]: http://tools.ietf.org/html/rfc5581
[RFC 6637]: http://tools.ietf.org/html/rfc6637
[dep]: https://github.com/golang/dep "golang/dep: Go dependency management tool"

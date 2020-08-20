# [gpgpdump] - OpenPGP packet visualizer

[![Build Status](https://travis-ci.org/spiegel-im-spiegel/gpgpdump.svg?branch=master)](https://travis-ci.org/spiegel-im-spiegel/gpgpdump)
[![GitHub license](https://img.shields.io/badge/license-Apache%202-blue.svg)](https://raw.githubusercontent.com/spiegel-im-spiegel/gpgpdump/master/LICENSE)
[![GitHub release](https://img.shields.io/github/release/spiegel-im-spiegel/gpgpdump.svg)](https://github.com/spiegel-im-spiegel/gpgpdump/releases/latest)

[gpgpdump] is a OpenPGP ([RFC 4880]) packet visualizer by [golang](https://golang.org/).

- [gpgpdump] is based on [pgpdump](https://github.com/kazu-yamamoto/pgpdump) design by [kazu-yamamoto](https://github.com/kazu-yamamoto).
- Command-line interface
- Output with plain text or [JSON](https://tools.ietf.org/html/rfc7159)-formatted text
- Support [RFC 5581] and [RFC 6637]
- Support a part of [RFC 4880bis]

## Download and Build

```
$ go get github.com/spiegel-im-spiegel/gpgpdump@latest
```

## Binaries

See [latest release](https://github.com/spiegel-im-spiegel/gpgpdump/releases/latest).

## Usage

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
  -c, --cert          dumps attested certification in signature packets (tag 2)
      --debug         for debug
  -f, --file string   path of OpenPGP file
  -h, --help          help for gpgpdump
      --indent int    indent size for output string
  -i, --int           dumps multi-precision integers
  -j, --json          output with JSON format
  -l, --literal       dumps literal packets (tag 11)
  -m, --marker        dumps marker packets (tag 10)
  -p, --private       dumps private packets (tag 60-63)
  -u, --utc           output with UTC time
  -v, --version       output version of gpgpdump

Use "gpgpdump [command] --help" for more information about a command.
```

### Output with plain text

```
$ cat testdata/eccsig.asc | gpgpdump -u --indent 2
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
```

### Output with JSON-formatted text

```
$ cat testdata/eccsig.asc | gpgpdump -j -u | jq .
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
  gpgpdump hkp [flags] <user ID or key ID>

Flags:
  -h, --help               help for hkp
      --keyserver string   OpenPGP key server (default "keys.gnupg.net")
      --port int           port number of OpenPGP key server (default 11371)
      --raw                output raw text from OpenPGP key server
      --secure             enable HKP over HTTPS

Global Flags:
  -a, --armor        accepts ASCII input only
  -c, --cert         dumps attested certification in signature packets (tag 2)
      --debug        for debug
      --indent int   indent size for output string
  -i, --int          dumps multi-precision integers
  -j, --json         output with JSON format
  -l, --literal      dumps literal packets (tag 11)
  -m, --marker       dumps marker packets (tag 10)
  -p, --private      dumps private packets (tag 60-63)
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
Signature Packet (tag 2) (140 bytes)
  Version: 4 (current)
  Signiture Type: Generic certification of a User ID and Public-Key packet (0x10)
  Public-key Algorithm: EdDSA (pub 22)
  Hash Algorithm: SHA2-256 (hash 8)
  Hashed Subpacket (52 bytes)
    Issuer Fingerprint (sub 33) (21 bytes)
      Version: 4 (need 20 octets length)
      Fingerprint (20 bytes)
        3b cc c7 cf d2 59 7e 53 44 dd 96 4a 72 9b 52 3d 11 f3 a8 d7
    Signature Creation Time (sub 2): 2020-06-22T01:57:38Z
    Notation Data (sub 20) (21 bytes)
      Flag: Human-readable
      Name: rem@gnupg.org
      Value (0 byte)
  Unhashed Subpacket (10 bytes)
    Issuer (sub 16): 0x729b523d11f3a8d7
  Hash left 2 bytes
    b1 15
  EdDSA compressed value r (256 bits)
  EdDSA compressed value s (256 bits)
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

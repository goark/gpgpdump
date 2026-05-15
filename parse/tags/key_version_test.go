package tags

import (
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/values"
)

func TestTag01FingerprintVer6(t *testing.T) {
	tag := &tag01{tagInfo{cxt: context.New(), reader: reader.New(make([]byte, 32))}}
	item, err := tag.fingerprint(6)
	if err != nil {
		t.Fatalf("fingerprint(6) error = %v", err)
	}
	if item == nil {
		t.Fatal("fingerprint(6) = nil, want non-nil")
	}
	if tag.reader.Rest() != 0 {
		t.Fatalf("reader.Rest() = %d, want 0", tag.reader.Rest())
	}
}

func TestTag04FingerprintVer6(t *testing.T) {
	tag := &tag04{tagInfo{cxt: context.New(), reader: reader.New(make([]byte, 32))}}
	item, err := tag.fingerprint(6)
	if err != nil {
		t.Fatalf("fingerprint(6) error = %v", err)
	}
	if item == nil {
		t.Fatal("fingerprint(6) = nil, want non-nil")
	}
	if tag.reader.Rest() != 0 {
		t.Fatalf("reader.Rest() = %d, want 0", tag.reader.Rest())
	}
}

func TestSub33Version6Note(t *testing.T) {
	body := append([]byte{0x06}, make([]byte, 32)...)
	s := newSub33(context.New(), values.SuboacketID(33), body)
	item, err := s.Parse()
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(item.Items) == 0 {
		t.Fatal("items is empty")
	}
	if item.Items[0].Note != "need 32 octets length" {
		t.Fatalf("Version note = %q, want %q", item.Items[0].Note, "need 32 octets length")
	}
}

func TestSub35Version6Note(t *testing.T) {
	body := append([]byte{0x06}, make([]byte, 32)...)
	s := newSub35(context.New(), values.SuboacketID(35), body)
	item, err := s.Parse()
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(item.Items) == 0 {
		t.Fatal("items is empty")
	}
	if item.Items[0].Note != "need 32 octets length" {
		t.Fatalf("Version note = %q, want %q", item.Items[0].Note, "need 32 octets length")
	}
}

func TestTag02Version6UsesV5Layout(t *testing.T) {
	// version(6), sig type, pubid(RSA), hashid, hashed len(4), unhashed len(4), hash left(2), salt(16), rsa sig mpi
	body := []byte{0x06, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	body = append(body, make([]byte, 16)...)
	body = append(body, []byte{0x00, 0x08, 0x01}...)
	op := &packet.OpaquePacket{Tag: 2, Contents: body}
	cxt := context.New(context.Set(context.DEBUG, true), context.Set(context.UTC, true))
	item, err := NewTag(op, cxt).Parse()
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !strings.Contains(item.String(), "Random values used as salt") {
		t.Fatal("output does not contain v5/v6 salt field")
	}
}

func TestTag03Version6UsesV5Layout(t *testing.T) {
	// version(6), count, symid, aeadid(EAX), count, s2k(simple,sha1), iv(16)
	body := []byte{0x06, 0x04, 0x09, 0x01, 0x02, 0x00, 0x02}
	body = append(body, make([]byte, 16)...)
	op := &packet.OpaquePacket{Tag: 3, Contents: body}
	cxt := context.New(context.Set(context.DEBUG, true), context.Set(context.UTC, true))
	item, err := NewTag(op, cxt).Parse()
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !strings.Contains(item.String(), "AEAD Algorithm") {
		t.Fatal("output does not contain v5/v6 AEAD field")
	}
}

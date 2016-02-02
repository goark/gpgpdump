package tag04

import (
	"strconv"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

// Tag04 - One-Pass Signature Packet
type Tag04 struct {
	*options.Options
	tag  values.Tag
	body []byte
}

//New return One-Pass Signature Packet
func New(opt *options.Options, tag values.Tag, body []byte) *Tag04 {
	return &Tag04{Options: opt, tag: tag, body: body}
}

// Parse parsing One-Pass Signature Packet
func (t Tag04) Parse() (*items.Item, error) {
	pckt := t.tag.Get(len(t.body))
	// [00] one-octet version number
	// [01] one-octet signature type
	// [02] one-octet number describing the hash algorithm used.
	// [03] one-octet number describing the public-key algorithm used.
	// [04] eight-octet number holding the Key ID of the signing key.
	// [12] one-octet number holding a flag showing whether the signature.
	version := values.OneSigVer(t.body[0])
	sig := values.SigType(t.body[1])
	hash := values.HashAlg(t.body[2])
	pub := values.PubAlg(t.body[3])
	keyID := values.KeyID(values.Octets2Int(t.body[4:12]))
	flag := t.body[12]

	pckt.AddSub(version.Get())
	pckt.AddSub(sig.Get())
	pckt.AddSub(hash.Get())
	pckt.AddSub(pub.Get())
	pckt.AddSub(keyID.Get())
	f := "other than one pass signature"
	if flag == 0 {
		f = "another one pass signature"
	}
	pckt.AddSub(items.NewItem("Encrypted session key", strconv.Itoa(int(flag)), f))
	return pckt, nil
}

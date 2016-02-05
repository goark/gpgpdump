package tag01

import (
	"bytes"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/pubkeys"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

// Tag01 - Public-Key Encrypted Session Key Packet
type Tag01 struct {
	*options.Options
	tag  values.Tag
	body []byte
}

//New return Public-Key Encrypted Session Key Packet
func New(opt *options.Options, tag values.Tag, body []byte) *Tag01 {
	return &Tag01{Options: opt, tag: tag, body: body}
}

// Parse parsing Public-Key Encrypted Session Key Packet
func (t Tag01) Parse() (*items.Item, error) {
	pckt := t.tag.Get(len(t.body))
	// [00] one-octet number giving the version number of the packet type.
	// [01] eight-octet number that gives the Key ID of the public key to which the session key is encrypted.
	// [09] one-octet number giving the public-key algorithm used.
	// [10] string of octets that is the encrypted session key.
	version := values.PubSessKeyVer(t.body[0])
	keyID := values.KeyID(values.Octets2Int(t.body[1:9]))
	pub := values.PubAlg(t.body[9])
	pubkey := pubkeys.New(t.Options, pub, bytes.NewReader(t.body[10:]))

	pckt.AddSub(version.Get())
	pckt.AddSub(keyID.Get())
	pckt.AddSub(pub.Get())
	pubkey.ParseSes(pckt)

	t.SetSymAlgModePubEnc()
	return pckt, nil
}

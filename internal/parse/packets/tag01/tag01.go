package tag01

import (
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/pubkeys"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
)

// Tag01 - Public-Key Encrypted Session Key Packet
type Tag01 struct {
	*options.Options
	body []byte
}

//New return Tag11
func New(opt *options.Options, body []byte) *Tag01 {
	return &Tag01{Options: opt, body: body}
}

// Parse parsing Literal Data Packet
func (t Tag01) Parse(indent values.Indent) (values.Content, error) {
	content := values.NewContent()
	// [00] one-octet number giving the version number of the packet type.
	// [01] eight-octet number that gives the Key ID of the public key to which the session key is encrypted.
	// [09] one-octet number giving the public-key algorithm used.
	// [10] string of octets that is the encrypted session key.

	version := values.PubSymKeyVer(t.body[0])
	keyID := values.KeyID(values.Octets2Int(t.body[1:9]))
	pub := values.PubAlg(t.body[9])
	pubkey := pubkeys.New(t.Options, pub, t.body[10:])

	content = append(content, (indent + 1).Fill(version.String()))
	content = append(content, (indent + 1).Fill(keyID.String()))
	content = append(content, (indent + 1).Fill(pub.String()))
	content = content.Add(pubkey.ParseSym(indent + 1))
	t.SetSymAlgModePubEnc()
	return content, nil
}

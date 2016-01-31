package tag06

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/pubkeys"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
)

// Tag06 - Public-Key Packet
type Tag06 struct {
	*options.Options
	body []byte
}

//New return Tag06
func New(opt *options.Options, body []byte) *Tag06 {
	return &Tag06{Options: opt, body: body}
}

// Parse parsing Public-Key Packet
func (t Tag06) Parse(indent values.Indent) (values.Content, error) {
	content := values.NewContent()

	version := values.PubVer(t.body[0])
	content = append(content, (indent + 1).Fill(version.String()))
	if version.IsOld() {
		c, err := t.parseV3(indent + 1)
		if err != nil {
			return content, err
		}
		content = content.Add(c)
	} else if version.IsNew() {
		c, err := t.parseV4(indent + 1)
		if err != nil {
			return content, err
		}
		content = content.Add(c)
	}
	return content, nil
}

func (t Tag06) parseV3(indent values.Indent) (values.Content, error) {
	content := values.NewContent()
	//Structure of Signiture Packet (Ver3)
	// [00] One-octet version number (3).
	// [01] four-octet number denoting the time that the key was created.
	// [05] two-octet number denoting the time in days that this key is valid.
	// [07] one-octet number denoting the public-key algorithm of this key.
	// [08] series of multiprecision integers comprising the key material
	creationTime := uint32(values.Octets2Int(t.body[1:5]))
	days := uint16(values.Octets2Int(t.body[5:7]))
	pub := values.PubAlg(t.body[7])
	pubkey := pubkeys.New(t.Options, pub, t.body[8:])

	content = append(content, indent.Fill(t.creationTime(creationTime)))
	content = append(content, indent.Fill(t.days(days)))
	content = append(content, indent.Fill(pub.String()))
	content = content.Add(pubkey.ParsePub(indent))
	return content, nil
}

func (t Tag06) parseV4(indent values.Indent) (values.Content, error) {
	content := values.NewContent()
	//Structure of Signiture Packet (Ver4)
	// [00] One-octet version number (4).
	// [01] four-octet number denoting the time that the key was created.
	// [05] one-octet number denoting the public-key algorithm of this key.
	// [06] series of multiprecision integers comprising the key material.
	creationTime := uint32(values.Octets2Int(t.body[1:5]))
	pub := values.PubAlg(t.body[5])
	pubkey := pubkeys.New(t.Options, pub, t.body[6:])

	content = append(content, indent.Fill(t.creationTime(creationTime)))
	content = append(content, indent.Fill(pub.String()))
	content = content.Add(pubkey.ParsePub(indent))
	return content, nil
}

func (t Tag06) creationTime(tm uint32) string {
	return fmt.Sprintf("Public key creation time - %s", values.StringRFC3339UNIX(tm, t.Uflag))
}

func (t Tag06) days(d uint16) string {
	return fmt.Sprintf("Valid days - %d[0 is forever]", d)
}

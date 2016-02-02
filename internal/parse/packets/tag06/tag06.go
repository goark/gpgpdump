package tag06

import (
	"strconv"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

// Tag06 - Public-Key Packet
type Tag06 struct {
	*options.Options
	tag  values.Tag
	body []byte
}

//New return Public-Key Packet
func New(opt *options.Options, tag values.Tag, body []byte) *Tag06 {
	return &Tag06{Options: opt, tag: tag, body: body}
}

// Parse parsing Public-Key Packet
func (t Tag06) Parse() (*items.Item, error) {
	pckt := t.tag.Get(len(t.body))

	version := values.SigVer(t.body[0])
	pckt.AddSub(version.Get())
	if version.IsOld() {
		return t.parseV3(pckt)
	} else if version.IsNew() {
		return t.parseV4(pckt)
	}
	return pckt, nil
}

func (t Tag06) parseV3(pckt *items.Item) (*items.Item, error) {
	//Structure of Signiture Packet (Ver3)
	// [00] One-octet version number (3).
	// [01] four-octet number denoting the time that the key was created.
	// [05] two-octet number denoting the time in days that this key is valid.
	// [07] one-octet number denoting the public-key algorithm of this key.
	// [08] series of multiprecision integers comprising the key material
	t.KeyCreationTime = values.Octets2Int(t.body[1:5])
	days := uint16(values.Octets2Int(t.body[5:7]))
	pub := values.PubAlg(t.body[7])
	//pubkey := pubkeys.New(t.Options, pub, t.body[8:])

	pckt.AddSub(values.PubKeyTime(t.KeyCreationTime, t.Uflag).Get())
	pckt.AddSub(items.NewItem("Valid days", strconv.Itoa(int(days)), "0 is forever"))
	pckt.AddSub(pub.Get())
	//pckt.AddSub(pubkey.ParsePub())
	return pckt, nil
}

func (t Tag06) parseV4(pckt *items.Item) (*items.Item, error) {
	//Structure of Signiture Packet (Ver4)
	// [00] One-octet version number (4).
	// [01] four-octet number denoting the time that the key was created.
	// [05] one-octet number denoting the public-key algorithm of this key.
	// [06] series of multiprecision integers comprising the key material.
	t.KeyCreationTime = values.Octets2Int(t.body[1:5])
	pub := values.PubAlg(t.body[5])
	//pubkey := pubkeys.New(t.Options, pub, t.body[6:])

	pckt.AddSub(values.PubKeyTime(t.KeyCreationTime, t.Uflag).Get())
	pckt.AddSub(pub.Get())
	//pckt.AddSub(pubkey.ParsePub())
	return pckt, nil
}

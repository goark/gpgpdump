package tag06

import (
	"bytes"
	"io"
	"strconv"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/pubkeys"
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
func (t *Tag06) Parse() (*items.Item, error) {
	pckt := t.tag.Get(len(t.body))
	reader := bytes.NewReader(t.body)

	if _, err := ParsePub(t.Options, reader, pckt); err != nil {
		return pckt, nil
	}

	//for debug
	//if reader.Len() > 0 {
	//	left := make([]byte, reader.Len())
	//	if _, err := reader.Read(left); err == nil {
	//		pckt.AddSub(values.NewRawData("Left", "", left, true).Get())
	//	}
	//}
	return pckt, nil
}

//ParsePub parsing Public-Key Packet
func ParsePub(opt *options.Options, reader *bytes.Reader, item *items.Item) (values.PubAlg, error) {
	v, err := reader.ReadByte()
	if err != nil {
		if err == io.EOF {
			return values.PubAlg(0), nil
		}
		return values.PubAlg(0), err
	}
	version := values.PubVer(v)
	item.AddSub(version.Get())
	if version.IsOld() {
		return parseV3(opt, reader, item)
	} else if version.IsNew() {
		return parseV4(opt, reader, item)
	}
	return values.PubAlg(0), nil
}

func parseV3(opt *options.Options, reader *bytes.Reader, item *items.Item) (values.PubAlg, error) {
	//Structure of Signiture Packet (Ver3)
	// [00] One-octet version number (3).
	// [01] four-octet number denoting the time that the key was created.
	// [05] two-octet number denoting the time in days that this key is valid.
	// [07] one-octet number denoting the public-key algorithm of this key.
	// [08] series of multiprecision integers comprising the key material
	var u [4]byte
	if _, err := reader.Read(u[0:]); err != nil {
		if err == io.EOF {
			return values.PubAlg(0), nil
		}
		return values.PubAlg(0), err
	}
	unix := values.PubKeyTime(u[:], opt.Uflag)
	opt.KeyCreationTime = unix.Unix()
	item.AddSub(unix.Get())

	var d [2]byte
	if _, err := reader.Read(d[0:]); err != nil {
		if err == io.EOF {
			return values.PubAlg(0), nil
		}
		return values.PubAlg(0), err
	}
	item.AddSub(items.NewItem("Valid days", strconv.Itoa(int(values.Octets2Int(d[:]))), "0 is forever", ""))

	p, err := reader.ReadByte()
	if err != nil {
		if err == io.EOF {
			return values.PubAlg(0), nil
		}
		return values.PubAlg(0), err
	}
	pub := values.PubAlg(p)
	item.AddSub(pub.Get())

	pubkey := pubkeys.New(opt, pub, reader)
	pubkey.ParsePub(item)
	return pub, nil
}

func parseV4(opt *options.Options, reader *bytes.Reader, item *items.Item) (values.PubAlg, error) {
	//Structure of Signiture Packet (Ver4)
	// [00] One-octet version number (4).
	// [01] four-octet number denoting the time that the key was created.
	// [05] one-octet number denoting the public-key algorithm of this key.
	// [06] series of multiprecision integers comprising the key material.
	var u [4]byte
	if _, err := reader.Read(u[0:]); err != nil {
		if err == io.EOF {
			return values.PubAlg(0), nil
		}
		return values.PubAlg(0), err
	}
	unix := values.PubKeyTime(u[:], opt.Uflag)
	opt.KeyCreationTime = unix.Unix()
	item.AddSub(unix.Get())

	p, err := reader.ReadByte()
	if err != nil {
		if err == io.EOF {
			return values.PubAlg(0), nil
		}
		return values.PubAlg(0), err
	}
	pub := values.PubAlg(p)
	item.AddSub(pub.Get())

	pubkey := pubkeys.New(opt, pub, reader)
	pubkey.ParsePub(item)
	return pub, nil
}

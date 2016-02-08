package tag05

import (
	"bytes"
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/pubkeys"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/s2k"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/tag06"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

// Tag05 - Secret-Key Packet
type Tag05 struct {
	*options.Options
	tag  values.Tag
	body []byte
}

//New return Secret-Key Packet
func New(opt *options.Options, tag values.Tag, body []byte) *Tag05 {
	return &Tag05{Options: opt, tag: tag, body: body}
}

// Parse parsing Secret-Key Packet
func (t Tag05) Parse() (*items.Item, error) {
	pckt := t.tag.Get(len(t.body))
	ver := t.body[0]
	reader := bytes.NewReader(t.body)

	pub := items.NewItem("Public-Key", "", "", "")
	p, err := tag06.ParsePub(t.Options, reader, pub)
	if err != nil {
		return pckt, err
	}
	pckt.AddSub(pub)

	sec := items.NewItem("Secret-Key", "", "", "")
	if err := ParseSec(t.Options, reader, sec, ver, p); err != nil {
		return pckt, err
	}
	pckt.AddSub(sec)

	//for debug
	//if reader.Len() > 0 {
	//	left := make([]byte, reader.Len())
	//	if _, err := reader.Read(left); err == nil {
	//		pckt.AddSub(values.NewRawData("Left", "", left, true).Get())
	//	}
	//}
	return pckt, nil
}

//ParseSec parsing Secret-Key Packet
func ParseSec(opt *options.Options, reader *bytes.Reader, item *items.Item, ver byte, pub values.PubAlg) error {
	version := values.PubVer(ver)
	s, err := reader.ReadByte()
	if err != nil {
		return err
	}
	switch s {
	case 1:
		item.Note = "the secret-key data is not encrypted."
		item.AddSub(version.Get())
		if !version.IsUnknown() {
			pubkey := pubkeys.New(opt, pub, reader)
			if err := pubkey.ParseSecPlain(item); err != nil {
				return err
			}
		} else {
			item.AddSub(unknownMPIs(int(ver), reader.Len()))
		}
	case 254, 255:
		if s == 254 {
			item.Note = "encrypted SHA1 hash"
		} else {
			item.Note = "encrypted checksum"
		}
		sy, err := reader.ReadByte()
		if err != nil {
			return err
		}
		sym := values.SymAlg(sy)
		item.AddSub(sym.Get())
		s2k := s2k.New(opt, reader)
		item.AddSub(s2k.Get())
		if s2k.HasIV() {
			iv := make([]byte, sym.IVLen())
			if _, err := reader.Read(iv); err != nil {
				return err
			}
			item.AddSub(values.NewRawData("IV", "", iv, true).Get())
		}
		if !version.IsUnknown() {
			pubkey := pubkeys.New(opt, pub, reader)
			if err := pubkey.ParseSecEnc(item); err != nil {
				return err
			}
		} else {
			item.AddSub(unknownMPIs(int(ver), reader.Len()))
		}
	default:
		item.Note = "Simple string-to-key for IDEA (encrypted checksum)."
		sym := values.SymAlg(s)
		item.AddSub(sym.Get())
		iv := make([]byte, sym.IVLen())
		if _, err := reader.Read(iv); err != nil {
			return err
		}
		item.AddSub(values.NewRawData("IV", "", iv, true).Get())
		if !version.IsUnknown() {
			pubkey := pubkeys.New(opt, pub, reader)
			if err := pubkey.ParseSecEnc(item); err != nil {
				return err
			}
		} else {
			item.AddSub(unknownMPIs(int(ver), reader.Len()))
		}
	}
	return nil
}

func unknownMPIs(ver, length int) *items.Item {
	return items.NewItem("Multi-precision integers", "", fmt.Sprintf("Unknown Version %d, %d bytes", ver, length), "")
}

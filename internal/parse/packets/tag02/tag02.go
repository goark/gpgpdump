package tag02

import (
	"bytes"
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/pubkeys"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/sub"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

// Tag02 - Signature Packet
type Tag02 struct {
	*options.Options
	tag  values.Tag
	body []byte
}

//New return Signature Packet
func New(opt *options.Options, tag values.Tag, body []byte) *Tag02 {
	return &Tag02{Options: opt, tag: tag, body: body}
}

// Parse parsing Signature Packet
func (t *Tag02) Parse() (*items.Item, error) {
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

func (t *Tag02) parseV3(pckt *items.Item) (*items.Item, error) {
	//Structure of Signiture Packet (Ver3)
	// [00] One-octet version number (3).
	// [01] One-octet length of following hashed material.  MUST be 5.
	//      [02] One-octet signature type.
	//      [03] Four-octet creation time.
	// [07] Eight-octet Key ID of signer.
	// [15] One-octet public-key algorithm.
	// [16] One-octet hash algorithm.
	// [17] Two-octet field holding left 16 bits of signed hash value.
	// [19] One or more multiprecision integers comprising the signature.
	size := t.body[1]

	hm := items.NewItem("Hashed material", "", fmt.Sprintf("%d bytes", size), "")
	if size != 5 { //MUST be 5
		hm.Value = "Unknown"
		hm.Dump = values.DumpByte(t.body[3 : 3+size])
		pckt.AddSub(hm)
		return pckt, nil
	}
	stype := values.SigType(t.body[2])
	unix := values.SigTime(t.body[3:7], t.Uflag)

	hm.AddSub(stype.Get())
	t.SigCreationTime = unix.Unix()
	hm.AddSub(unix.Get())
	pckt.AddSub(hm)

	keyID := values.KeyID(values.Octets2Int(t.body[7:15]))
	pub := values.PubAlg(t.body[15])
	hash := values.HashAlg(t.body[16])
	hashTag := t.body[17:19]
	pubkey := pubkeys.New(t.Options, pub, bytes.NewReader(t.body[19:]))

	pckt.AddSub(keyID.Get())
	pckt.AddSub(pub.Get())
	pckt.AddSub(hash.Get())
	pckt.AddSub(t.hashLeft2(hashTag).Get())
	pubkey.ParseSig(pckt)
	return pckt, nil
}

func (t *Tag02) parseV4(pckt *items.Item) (*items.Item, error) {
	//Structure of Signiture Packet (Ver4)
	// [00] One-octet version number (4).
	// [01] One-octet signature type.
	// [02] One-octet public-key algorithm.
	// [03] One-octet hash algorithm.
	// [04] Two-octet scalar octet count for following hashed subpacket data.(= HS)
	// [06] Hashed subpacket data set (zero or more subpackets).
	// [06+HS] Two-octet scalar octet count for the following unhashed subpacket data.(= US)
	// [08+HS] Unhashed subpacket data set (zero or more subpackets).
	// [08+HS+US] Two-octet field holding the left 16 bits of the signed hash value.
	// [10+HS+US] One or more multiprecision integers comprising the signature.
	stype := values.SigType(t.body[1])
	pub := values.PubAlg(t.body[2])
	hash := values.HashAlg(t.body[3])
	sizeHS := values.Octets2Int(t.body[4:6])
	sizeUS := values.Octets2Int(t.body[6+sizeHS : 6+sizeHS+2])
	hashTag := t.body[8+sizeHS+sizeUS : 8+sizeHS+sizeUS+2]
	pubkey := pubkeys.New(t.Options, pub, bytes.NewReader(t.body[10+sizeHS+sizeUS:]))

	pckt.AddSub(stype.Get())
	pckt.AddSub(pub.Get())
	pckt.AddSub(hash.Get())
	if sizeHS > 0 {
		sp, err := sub.New(t.Options, "Hashed Subpacket", t.body[6:6+sizeHS])
		if err != nil {
			return pckt, err
		}
		if err := ParseSub(sp, pckt); err != nil {
			return pckt, err
		}
	}
	if sizeUS > 0 {
		sp, err := sub.New(t.Options, "Unhashed Subpacket", t.body[8+sizeHS:8+sizeHS+sizeUS])
		if err != nil {
			return pckt, err
		}
		if err := ParseSub(sp, pckt); err != nil {
			return pckt, err
		}
	}
	pckt.AddSub(t.hashLeft2(hashTag).Get())
	pubkey.ParseSig(pckt)
	return pckt, nil
}

func (t *Tag02) hashLeft2(h []byte) *values.RawData {
	return values.NewRawData("Hash left 2 bytes", "", h, true)
}

package tag02

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/pubkeys"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
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
func (t Tag02) Parse(indent values.Indent) (values.Content, error) {
	content := values.NewContent()

	version := values.SigVer(t.body[0])
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

func (t Tag02) parseV3(indent values.Indent) (values.Content, error) {
	content := values.NewContent()
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
	stype := values.SigType(t.body[2])
	t.SigCreationTime = values.Octets2Int(t.body[3:7])
	keyID := values.KeyID(values.Octets2Int(t.body[7:15]))
	pub := values.PubAlg(t.body[15])
	hash := values.HashAlg(t.body[16])
	hashTag := t.body[17:19]
	pubkey := pubkeys.New(t.Options, pub, t.body[19:])

	content = append(content, indent.Fill(t.hashedMaterialSize(size)))
	if size == 5 { //MUST be 5
		content = append(content, (indent + 1).Fill(t.sigType(stype)))
		content = append(content, (indent + 1).Fill(values.SigTime(t.SigCreationTime, t.Uflag).String()))
	} else {
		content = append(content, (indent + 1).Fill("Unknown"))
		return content, nil
	}
	content = append(content, indent.Fill(keyID.String()))
	content = append(content, indent.Fill(pub.String()))
	content = append(content, indent.Fill(hash.String()))
	content = append(content, indent.Fill(t.hashLeft2(hashTag)))
	content = content.Add(pubkey.ParseSig(indent))
	return content, nil
}

func (t Tag02) parseV4(indent values.Indent) (values.Content, error) {
	content := values.NewContent()

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
	hasTag := t.body[8+sizeHS+sizeUS : 8+sizeHS+sizeUS+2]
	pubkey := pubkeys.New(t.Options, pub, t.body[10+sizeHS+sizeUS:])

	content = append(content, indent.Fill(t.sigType(stype)))
	content = append(content, indent.Fill(pub.String()))
	content = append(content, indent.Fill(hash.String()))
	if sizeHS > 0 {
		sp, err := NewSubpackets(t.Options, "Hashed Subpacket -", t.body[6:6+sizeHS])
		if err != nil {
			return content, err
		}
		content = content.Add(sp.Parse(indent))
	}
	if sizeUS > 0 {
		sp, err := NewSubpackets(t.Options, "Unhashed Subpacket -", t.body[8+sizeHS:8+sizeHS+sizeUS])
		if err != nil {
			return content, err
		}
		content = content.Add(sp.Parse(indent))
	}
	content = append(content, indent.Fill(t.hashLeft2(hasTag)))
	content = content.Add(pubkey.ParseSig(indent))
	return content, nil
}

func (t Tag02) sigType(st values.SigType) string {
	return fmt.Sprintf("Signature type - %v", st)
}

func (t Tag02) hashLeft2(h []byte) string {
	return fmt.Sprintf("Hash left 2 bytes - %s", values.DumpByte(h))
}

func (t Tag02) hashedMaterialSize(size byte) string {
	return fmt.Sprintf("Hashed material(%d bytes):", size)
}

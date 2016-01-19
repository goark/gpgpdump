package parse

import (
	"fmt"

	"golang.org/x/crypto/openpgp/packet"
)

// Tag02 - Signature Packet
type Tag02 struct {
	*Options
	OpaquePacket *packet.OpaquePacket
	version      SigVer
}

// Parse parsing Signature Packet
func (t Tag02) Parse(indent Indent) ([]string, error) {
	var content = make([]string, 0)
	content = append(content, indent.Fill(StringPacketInfo(t.OpaquePacket)))

	indent++
	t.version = SigVer(t.OpaquePacket.Contents[0])
	content = append(content, indent.Fill(t.ver()))
	if t.version.IsOld() {
		c, err := t.parseSigV3(indent)
		if err != nil {
			return content, err
		}
		content = append(content, c...)
	} else if t.version.IsNew() {
		c, err := t.parseSigV4(indent)
		if err != nil {
			return content, err
		}
		content = append(content, c...)
	}

	return content, nil
}

func (t Tag02) parseSigV4(indent Indent) ([]string, error) {
	var content = make([]string, 0)

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
	stype := SigType(t.OpaquePacket.Contents[1])
	pub := PubAlg(t.OpaquePacket.Contents[2])
	hash := HashAlg(t.OpaquePacket.Contents[3])
	sizeHS := Octets2Int(t.OpaquePacket.Contents[4:6])
	sizeUS := Octets2Int(t.OpaquePacket.Contents[6+sizeHS : 6+sizeHS+2])
	hasTag := t.OpaquePacket.Contents[8+sizeHS+sizeUS : 8+sizeHS+sizeUS+2]
	pubkeyMPI := &PubkeyMPI{Options: t.Options, Pub: pub, MPI: t.OpaquePacket.Contents[10+sizeHS+sizeUS:]}

	content = append(content, indent.Fill(t.sigType(stype)))
	content = append(content, indent.Fill(t.pubAlg(pub)))
	content = append(content, indent.Fill(t.hashAlg(hash)))
	if sizeHS > 0 {
		osp, err := packet.OpaqueSubpackets(t.OpaquePacket.Contents[6 : 6+sizeHS])
		if err != nil {
			return content, err
		}
		sp := &Subpackets{Options: t.Options, Title: "Hashed Subpacket -", OpaqueSubpackets: osp}
		content = append(content, sp.Parse(indent)...)
	}
	if sizeUS > 0 {
		osp, err := packet.OpaqueSubpackets(t.OpaquePacket.Contents[8+sizeHS : 8+sizeHS+sizeUS])
		if err != nil {
			return content, err
		}
		sp := &Subpackets{Options: t.Options, Title: "Unhashed Subpacket -", OpaqueSubpackets: osp}
		content = append(content, sp.Parse(indent)...)
	}
	content = append(content, indent.Fill(t.hashLeft2(hasTag)))
	content = append(content, pubkeyMPI.Parse(indent)...)
	return content, nil
}

func (t Tag02) parseSigV3(indent Indent) ([]string, error) {
	var content = make([]string, 0)
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
	size := t.OpaquePacket.Contents[1]
	stype := SigType(t.OpaquePacket.Contents[2])
	creationTime := int64(Octets2Int(t.OpaquePacket.Contents[3:7]))
	keyID := KeyID(Octets2Int(t.OpaquePacket.Contents[7:15]))
	pub := PubAlg(t.OpaquePacket.Contents[15])
	hash := HashAlg(t.OpaquePacket.Contents[16])
	hashTag := t.OpaquePacket.Contents[17:19]
	pubkeyMPI := &PubkeyMPI{Options: t.Options, Pub: pub, MPI: t.OpaquePacket.Contents[19:]}
	content = append(content, indent.Fill(t.hashedMaterialSize(size)))
	if size == 5 { //MUST be 5
		content = append(content, (indent + 1).Fill(t.sigType(stype)))
		content = append(content, (indent + 1).Fill(t.creationTime(creationTime)))
	} else {
		content = append(content, (indent + 1).Fill("Unknown"))
		return content, nil
	}
	content = append(content, indent.Fill(t.keyID(KeyID(keyID))))
	content = append(content, indent.Fill(t.pubAlg(pub)))
	content = append(content, indent.Fill(t.hashAlg(hash)))
	content = append(content, indent.Fill(t.hashLeft2(hashTag)))
	content = append(content, pubkeyMPI.Parse(indent)...)
	return content, nil
}

func (t Tag02) ver() string {
	return fmt.Sprintf("Ver %v", t.version)
}

func (t Tag02) sigType(st SigType) string {
	return fmt.Sprintf("Signature type - %v", st)
}

func (t Tag02) pubAlg(pa PubAlg) string {
	return fmt.Sprintf("Public-key algorithm - %v", pa)
}

func (t Tag02) hashAlg(ha HashAlg) string {
	return fmt.Sprintf("Hash algorithm - %v", ha)
}

func (t Tag02) hashLeft2(h []byte) string {
	return fmt.Sprintf("Hash left 2 bytes - %s", DumpByte(h))
}

func (t Tag02) hashedMaterialSize(size byte) string {
	return fmt.Sprintf("Hashed material(%d bytes):", size)
}

func (t Tag02) creationTime(tm int64) string {
	return fmt.Sprintf("Creation time - %s", StringRFC3339UNIX64(tm, t.Uflag))
}

func (t Tag02) keyID(kid KeyID) string {
	return fmt.Sprintf("Key ID of signer - %v", kid)
}

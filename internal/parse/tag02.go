package parse

import (
	"bytes"
	"fmt"
	"time"

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
	}

	return content, nil
}

func (t Tag02) parseSigV3(indent Indent) ([]string, error) {
	var content = make([]string, 0)
	p, err := t.OpaquePacket.Parse()
	if err != nil {
		return content, err
	}
	switch pkt := p.(type) {
	case *packet.SignatureV3:
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
		pub := PubAlg(t.OpaquePacket.Contents[15])
		hash := HashAlg(t.OpaquePacket.Contents[16])
		mpi := t.OpaquePacket.Contents[19:]
		content = append(content, indent.Fill(t.hashedMaterialSize(size)))
		if size == 5 { //MUST be 5
			content = append(content, (indent + 1).Fill(t.sigType(SigType(t.OpaquePacket.Contents[2]))))
			content = append(content, (indent + 1).Fill(t.creationTime(pkt.CreationTime)))
		} else {
			content = append(content, (indent + 1).Fill("Unknown"))
			return content, nil
		}
		content = append(content, indent.Fill(t.keyID(KeyID(pkt.IssuerKeyId))))
		content = append(content, indent.Fill(t.pubAlg(pub)))
		content = append(content, indent.Fill(t.hashAlg(hash)))
		content = append(content, indent.Fill(t.hashLeft2(pkt.HashTag[:])))
		if pub.IsDSA() {
			c := t.mpiDSA(mpi)
			for _, l := range c {
				content = append(content, indent.Fill(l))
			}
			content = append(content, (indent + 1).Fill("-> hash(DSA q bits)"))
		} else if pub.IsRSA() {
			c := t.mpiRSA(mpi)
			for _, l := range c {
				content = append(content, indent.Fill(l))
			}
			content = append(content, (indent + 1).Fill("-> PKCS-1"))
		}
	default:
		content = append(content, indent.Fill("Unknown"))
	}
	return content, nil
}

func (t Tag02) ver() string {
	return fmt.Sprintf("Ver - %v", t.version)
}

func (t Tag02) hashedMaterialSize(size byte) string {
	return fmt.Sprintf("Hashed material(%d bytes):", size)
}

func (t Tag02) sigType(st SigType) string {
	return fmt.Sprintf("Sig type - %v", st)
}

func (t Tag02) creationTime(tm time.Time) string {
	return fmt.Sprintf("Creation time - %s", StringRFC3339(tm, t.Uflag))
}

func (t Tag02) keyID(kid KeyID) string {
	return fmt.Sprintf("Key ID - %v", kid)
}

func (t Tag02) pubAlg(pa PubAlg) string {
	return fmt.Sprintf("Pub alg - %v", pa)
}

func (t Tag02) hashAlg(ha HashAlg) string {
	return fmt.Sprintf("Hash alg - %v", ha)
}

func (t Tag02) hashLeft2(h []byte) string {
	return fmt.Sprintf("Hash left 2 bytes - %s", DumpByte(h))
}

func (t Tag02) mpiDSA(mpi []byte) []string {
	var content = make([]string, 0)
	reader := bytes.NewReader(mpi)
	dsaMPI := &DSASigMPI{}
	if err := dsaMPI.Get(reader); err != nil {
		content = append(content, err.Error())
	} else {
		content = append(content, dsaMPI.DSASigR.Dump("DSA r", t.Iflag))
		content = append(content, dsaMPI.DSASigS.Dump("DSA s", t.Iflag))
	}
	return content
}

func (t Tag02) mpiRSA(mpi []byte) []string {
	var content = make([]string, 0)
	reader := bytes.NewReader(mpi)
	rsaMPI := &RSASigMPI{}
	if err := rsaMPI.Get(reader); err != nil {
		content = append(content, err.Error())
	} else {
		content = append(content, rsaMPI.RSASignature.Dump("RSA m^d mod n", t.Iflag))
	}
	return content
}

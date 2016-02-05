package sub

import (
	"fmt"

	"golang.org/x/crypto/openpgp/packet"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

var subpacketNames = values.Msgs{
	0:  "Reserved",                               //00
	1:  "Image Attribute",                        //01
	2:  "Signature Creation Time",                //02
	3:  "Signature Expiration Time",              //03
	4:  "Exportable Certification",               //04
	5:  "Trust Signature",                        //05
	6:  "Regular Expression",                     //06
	7:  "Revocable",                              //07
	8:  "Reserved",                               //08
	9:  "Key Expiration Time",                    //09
	10: "Placeholder for backward compatibility", //10
	11: "Preferred Symmetric Algorithms",         //11
	12: "Revocation Key",                         //12
	13: "Reserved",                               //13
	14: "Reserved",                               //14
	15: "Reserved",                               //15
	16: "Issuer",                                 //16
	17: "Reserved",                               //17
	18: "Reserved",                               //18
	19: "Reserved",                               //19
	20: "Notation Data",                          //20
	21: "Preferred Hash Algorithms",              //21
	22: "Preferred Compression Algorithms",       //22
	23: "Key Server Preferences",                 //23
	24: "Preferred Key Server",                   //24
	25: "Primary User ID",                        //25
	26: "Policy URI",                             //26
	27: "Key Flags",                              //27
	28: "Signer's User ID",                       //28
	29: "Reason for Revocation",                  //29
	30: "Features",                               //30
	31: "Signature Target",                       //31
	32: "Embedded Signature",                     //32
}

// PacketType is sub packet type
type PacketType byte

// Get returns Item instance
func (s PacketType) Get() *items.Item {
	return items.NewItem(s.String(), "", "", "")
}

func (s PacketType) String() string {
	var name string
	if 100 <= s && s <= 110 {
		name = "Private or experimental"
	} else {
		name = subpacketNames.Get(int(s), "Unknown")
	}
	return fmt.Sprintf("%s (sub %d)", name, s)
}

// Packets - Sub Packets
type Packets struct {
	*options.Options
	Title            string
	OpaqueSubpackets []*packet.OpaqueSubpacket
}

//New returns new Packets instance
func New(opt *options.Options, title string, body []byte) (*Packets, error) {
	osp, err := packet.OpaqueSubpackets(body)
	if err != nil {
		return nil, err
	}
	return &Packets{Options: opt, Title: title, OpaqueSubpackets: osp}, nil
}

// ParseSubpacket is function value of parsing sub-packet
type ParseSubpacket func(*Packets, *packet.OpaqueSubpacket, *items.Item) error

//Functions is type of function list.
type Functions map[int]ParseSubpacket

//Get returns message.
func (fs Functions) Get(i int, def ParseSubpacket) ParseSubpacket {
	if f, ok := fs[i]; ok {
		return f
	}
	return def
}

//ParseSPReserved parsing "Reserved" sub packet
func ParseSPReserved(sp *Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := PacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))
	item.AddSub(st)
	return nil
}

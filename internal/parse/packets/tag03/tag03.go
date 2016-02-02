package tag03

import (
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/s2k"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

// Tag03 - Symmetric-Key Encrypted Session Key Packet
type Tag03 struct {
	*options.Options
	tag  values.Tag
	body []byte
}

//New return ymmetric-Key Encrypted Session Key Packet
func New(opt *options.Options, tag values.Tag, body []byte) *Tag03 {
	return &Tag03{Options: opt, tag: tag, body: body}
}

// Parse parsing Symmetric-Key Encrypted Session Key Packet
func (t Tag03) Parse() (*items.Item, error) {
	pckt := t.tag.Get(len(t.body))
	// [00] one-octet version number
	// [01] one-octet number describing the symmetric algorithm used.
	// [02] string-to-key (S2K) specifier
	version := values.SymSessKeyVer(t.body[0])
	sym := values.SymAlg(t.body[1])
	s2k := s2k.New(t.Options, t.body[2:])

	pckt.AddSub(version.Get())
	pckt.AddSub(sym.Get())
	//pckt.AddSub(s2k.Parse())
	if s2k.Left() > 0 {
		pckt.AddSub(items.NewItem("Encrypted session key", "", "sym alg(1 bytes) + session key"))
	}
	t.SetSymAlgModeSymEnc()
	return pckt, nil
}

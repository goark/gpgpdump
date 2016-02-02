package tag03

import (
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/s2k"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
)

// Tag03 - Symmetric-Key Encrypted Session Key Packet
type Tag03 struct {
	*options.Options
	body []byte
}

//New return Tag03
func New(opt *options.Options, body []byte) *Tag03 {
	return &Tag03{Options: opt, body: body}
}

// Parse parsing Symmetric-Key Encrypted Session Key Packet
func (t Tag03) Parse(indent values.Indent) (values.Content, error) {
	content := values.NewContent()
	// [00] one-octet version number
	// [01] one-octet number describing the symmetric algorithm used.
	// [02] string-to-key (S2K) specifier

	version := values.SymSessKeyVer(t.body[0])
	sym := values.SymAlg(t.body[1])
	s2k := s2k.New(t.Options, t.body[2:])

	content = append(content, (indent + 1).Fill(version.String()))
	content = append(content, (indent + 1).Fill(sym.String()))
	content = content.Add(s2k.Parse(indent + 1))
	if s2k.Left() > 0 {
		content = append(content, (indent + 1).Fill("Encrypted session key (sym alg(1 bytes) + session key)"))
	}
	t.SetSymAlgModeSymEnc()
	return content, nil
}

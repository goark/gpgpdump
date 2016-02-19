package tag09

import (
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

// Tag09 - Symmetrically Encrypted Data Packet
type Tag09 struct {
	*options.Options
	tag  values.Tag
	body []byte
}

//New return Symmetrically Encrypted Data Packet
func New(opt *options.Options, tag values.Tag, body []byte) *Tag09 {
	return &Tag09{Options: opt, tag: tag, body: body}
}

// Parse parsing Symmetrically Encrypted Data Packe
func (t *Tag09) Parse() (*items.Item, error) {
	pckt := t.tag.Get(len(t.body))

	switch true {
	case t.Mode.IsSymEnc():
		pckt.AddSub(items.NewItem("Encrypted data", "", "sym alg is specified in sym-key encrypted session key", ""))
	case t.Mode.IsPubEnc():
		pckt.AddSub(items.NewItem("Encrypted data", "", "sym alg is specified in pub-key encrypted session key", ""))
	default:
		pckt.AddSub(items.NewItem("Encrypted data", "", "sym alg is IDEA, simple string-to-key", ""))
	}
	t.ResetSymAlgMode()
	return pckt, nil
}

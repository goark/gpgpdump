package private

import (
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

// Private - Private Packet
type Private struct {
	*options.Options
	tag  values.Tag
	body []byte
}

//New return Private Packet
func New(opt *options.Options, tag values.Tag, body []byte) *Private {
	return &Private{Options: opt, tag: tag, body: body}
}

// Parse parsing Private Packet
func (t *Private) Parse() (*items.Item, error) {
	pckt := t.tag.Get(len(t.body))
	pckt.Dump = values.NewRawData("Private", "", t.body, t.Pflag).Get().Dump
	return pckt, nil
}

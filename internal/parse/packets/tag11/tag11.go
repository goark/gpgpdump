package tag11

import (
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

// Tag11 - Literal Data Packet
type Tag11 struct {
	*options.Options
	tag  values.Tag
	body []byte
}

//New return Literal Data Packet
func New(opt *options.Options, tag values.Tag, body []byte) *Tag11 {
	return &Tag11{Options: opt, tag: tag, body: body}
}

// Parse parsing Literal Data Packet
func (t Tag11) Parse() (*items.Item, error) {
	pckt := t.tag.Get(len(t.body))

	f := values.LiteralFormat(t.body[0])
	flen := int(t.body[1])
	filename := values.LiteralFname(t.body[2 : 2+flen])
	ftime := values.FileTime(t.body[2+flen:2+flen+4], t.Uflag)
	data := values.LiteralData(t.body[2+flen+4:], t.Lflag)

	pckt.AddSub(f.Get())
	pckt.AddSub(filename.Get())
	pckt.AddSub(ftime.Get())
	pckt.AddSub(data.Get())
	return pckt, nil
}

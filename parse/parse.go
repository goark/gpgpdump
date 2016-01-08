package parse

import (
	"io"

	"github.com/spiegel-im-spiegel/gpgpdump/parse/packets"

	"golang.org/x/crypto/openpgp/packet"
)

func (c *Context) parse(body io.Reader) error {
	cxt := &packets.Context{}
	cxt.Hflag = c.Hflag
	cxt.Vflag = c.Vflag
	cxt.Aflag = c.Aflag
	cxt.Gflag = c.Gflag
	cxt.Iflag = c.Iflag
	cxt.Lflag = c.Lflag
	cxt.Mflag = c.Mflag
	cxt.Pflag = c.Pflag
	cxt.Uflag = c.Uflag

	oReader := packet.NewOpaqueReader(body)
	for {
		oPacket, err := oReader.Next()
		if err != nil {
			if err != io.EOF {
				return err
			}
			break
		}
		cxt.OpaquePacket = oPacket
		var content []string
		switch oPacket.Tag {
		case 11:
			content, err = packets.Tag11(cxt, 0)
		default:
			content, err = packets.Unknown(cxt, 0)
		}
		for _, line := range content {
			c.Outputln(line)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

package parse

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"

	"github.com/spiegel-im-spiegel/gocli"
)

// Errors
var (
	ErrNotArmor = errors.New("binary input is not allowed")
)

// Options for gpgpdump
type Options struct {
	Hflag bool //displays this help
	Vflag bool //displays version
	Aflag bool //accepts ASCII input only
	Gflag bool //selects alternate dump format
	Iflag bool //dumps integer packets
	Lflag bool //dumps literal packets
	Mflag bool //dumps marker packets
	Pflag bool //dumps private packets
	Uflag bool //displays UTC time
}

// Context for gpgpdump
type Context struct {
	*gocli.UI
	*Options
	InputFile string
}

// Command returns a new Context instance
func Command(ui *gocli.UI) *Context {
	return &Context{UI: ui, Options: &Options{}}
}

// Run Application
func (c *Context) Run() error {
	data, err := c.readData() //buffering
	if err != nil {
		return err
	}

	reader := bytes.NewReader(data)
	if err := c.parseArmor(reader); err != nil {
		if err != io.EOF {
			return err
		}
		if c.Aflag {
			return ErrNotArmor
		}
		reader := bytes.NewReader(data)
		if err := c.parseBinary(reader); err != nil {
			return err
		}
	}
	return nil
}

func (c *Context) readData() ([]byte, error) {
	if c.InputFile != "" {
		file, err := os.Open(c.InputFile) //maybe file path
		if err != nil {
			return nil, err
		}
		defer file.Close()
		c.Reader = file
	}
	return ioutil.ReadAll(c.Reader) //buffering
}

func (c *Context) parseArmor(reader io.Reader) error {
	block, err := armor.Decode(reader)
	if err != nil {
		return err
	}
	return c.parse(block.Body)
}

func (c *Context) parseBinary(reader io.Reader) error {
	return c.parse(reader)
}

func (c *Context) parse(body io.Reader) error {
	oReader := packet.NewOpaqueReader(body)
	for {
		oPacket, err := oReader.Next()
		if err != nil {
			if err != io.EOF {
				return err
			}
			break
		}
		var content []string
		switch oPacket.Tag {
		case 2:
			content, err = Tag02{Options: c.Options, OpaquePacket: oPacket}.Parse(0)
		case 11:
			content, err = Tag11{Options: c.Options, OpaquePacket: oPacket}.Parse(0)
		default:
			content, err = Unknown{Options: c.Options, OpaquePacket: oPacket}.Parse(0)
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

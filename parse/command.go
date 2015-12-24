package parse

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"os"

	"github.com/spiegel-im-spiegel/gocli"
)

// Errors
var (
	ErrNotArmor = errors.New("binary input is not allowed")
)

// Context for gpgpdump
type Context struct {
	*gocli.UI
	Hflag     bool //displays this help
	Vflag     bool //displays version
	Aflag     bool //accepts ASCII input only
	Gflag     bool //selects alternate dump format
	Iflag     bool //dumps integer packets
	Lflag     bool //dumps literal packets
	Mflag     bool //dumps marker packets
	Pflag     bool //dumps private packets
	Uflag     bool //displays UTC time
	InputFile string
}

// Command returns a new Context instance
func Command(ui *gocli.UI) *Context {
	return &Context{UI: ui}
}

// Run Application
func (c *Context) Run() error {
	if c.InputFile != "" {
		file, err := os.Open(c.InputFile) //maybe file path
		if err != nil {
			return err
		}
		defer file.Close()
		c.Reader = file
	}
	data, err := ioutil.ReadAll(c.Reader) //buffering
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

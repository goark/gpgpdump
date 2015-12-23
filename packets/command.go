package packets

import "github.com/spiegel-im-spiegel/gocli"

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
func (c *Context) Run() (int, error) {
	c.Outputln("Normal End")
	return 0, nil
}

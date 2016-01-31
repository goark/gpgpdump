package options

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

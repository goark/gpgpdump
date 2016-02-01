package options

//SymAlgMode -Sym. algorithm mode
type SymAlgMode int

// constant
const (
	SymAlgModeNotSpecified = SymAlgMode(0)
	SymAlgModeSymEnc       = SymAlgMode(1)
	SymAlgModePubEnc       = SymAlgMode(2)
)

//IsSymEnc return boolean for SymEnc
func (m SymAlgMode) IsSymEnc() bool {
	return m == SymAlgModeSymEnc
}

//IsPubEnc return boolean for PubEnc
func (m SymAlgMode) IsPubEnc() bool {
	return m == SymAlgModePubEnc
}

// Options for gpgpdump
type Options struct {
	Hflag           bool //displays this help
	Vflag           bool //displays version
	Aflag           bool //accepts ASCII input only
	Gflag           bool //selects alternate dump format
	Iflag           bool //dumps integer packets
	Lflag           bool //dumps literal packets
	Mflag           bool //dumps marker packets
	Pflag           bool //dumps private packets
	Uflag           bool //displays UTC time
	SigCreationTime int64
	KeyCreationTime int64
	Mode            SymAlgMode
}

//GetSymAlgMode get SymAlgMode
func (opt *Options) GetSymAlgMode() SymAlgMode {
	return opt.Mode
}

//ResetSymAlgMode reset SymAlgMode
func (opt *Options) ResetSymAlgMode() {
	opt.Mode = SymAlgModeNotSpecified
}

//SetSymAlgModeSymEnc set SymAlgMode to SymAlgModeSymEnc
func (opt *Options) SetSymAlgModeSymEnc() {
	opt.Mode = SymAlgModeSymEnc
}

//SetSymAlgModePubEnc set SymAlgMode to SymAlgModePubEnc
func (opt *Options) SetSymAlgModePubEnc() {
	opt.Mode = SymAlgModePubEnc
}

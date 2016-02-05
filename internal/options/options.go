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

func (m SymAlgMode) String() string {
	switch true {
	case m.IsPubEnc():
		return "Pubkey Encryption Mode"
	case m.IsSymEnc():
		return "Sym. Encryption Mode"
	default:
		return "Not Specified"
	}
}

// Options for gpgpdump
type Options struct {
	Hflag           bool //output this help
	Vflag           bool //output version
	Aflag           bool //accepts ASCII input only
	Gflag           bool //selects alternate dump format (not used)
	Iflag           bool //dumps multi-precision integers
	Jflag           bool //output with JSON format
	Lflag           bool //dumps literal packets (tag 11)
	Mflag           bool //dumps marker packets (tag 10)
	Pflag           bool //dumps private packets (tag 60-63)
	Uflag           bool //output UTC time
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

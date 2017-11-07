package facade

//ExitCode is OS exit code enumeration class
type ExitCode int

const (
	//ExitNormal is OS exit code "normal"
	ExitNormal ExitCode = iota
	//ExitAbnormal is OS exit code "abnormal"
	ExitAbnormal
)

//Int convert integer value
func (c ExitCode) Int() int {
	return int(c)
}

//Stringer method
func (c ExitCode) String() string {
	switch c {
	case ExitNormal:
		return "normal end"
	case ExitAbnormal:
		return "abnormal end"
	default:
		return "unknown"
	}
}

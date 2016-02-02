package values

import (
	"time"

	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

//UNIXTime - UNIX Time
type UNIXTime struct {
	name string
	unix int64
	utc  bool
}

//NewUNIXTime returns new UNIXTime
func NewUNIXTime(name string, unix uint64, utc bool) UNIXTime {
	return UNIXTime{name: name, unix: int64(unix), utc: utc}
}

// RFC3339 returns string with RFC3339 format
func (u UNIXTime) RFC3339() string {
	t := time.Unix(u.unix, 0)
	if u.utc {
		t = t.In(time.UTC)
	}
	return t.Format(time.RFC3339)
}

// Get returns Item instance
func (u UNIXTime) Get() *items.Item {
	return items.NewItem(u.name, u.RFC3339(), "")
}

//FileTime returns UNIXTime instance for Modification time of a file
func FileTime(unix uint64, utc bool) UNIXTime {
	return NewUNIXTime("Modification time of a file", unix, utc)
}

//PubKeyTime returns UNIXTime instance for Public key creation time
func PubKeyTime(unix uint64, utc bool) UNIXTime {
	return NewUNIXTime("Public key creation time", unix, utc)
}

//SigTime returns UNIXTime instance for Signature creation time
func SigTime(unix uint64, utc bool) UNIXTime {
	return NewUNIXTime("Signature creation time", unix, utc)
}

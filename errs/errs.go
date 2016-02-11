package errs

import (
	"errors"

	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

// Errors
var (
	ErrNotArmor     = errors.New("binary input is not allowed")
	ErrPanicOccured = errors.New("panic occured")
)

//ErrPacketInvalidData - invalid data error for parsing packets
type ErrPacketInvalidData string

// Get returns Item instance
func (e ErrPacketInvalidData) Get() *items.Item {
	return items.NewItem("Error", e.Error(), "", "")
}

func (e ErrPacketInvalidData) Error() string {
	return "invalid data: " + string(e)
}

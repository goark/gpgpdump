package values

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

//Msgs is type of message list.
type Msgs map[int]string

//Get returns message.
func (m Msgs) Get(i int, def string) string {
	if msg, ok := m[i]; ok {
		return msg
	}
	return def
}

// KeyID is Key ID
type KeyID uint64

//Get returns Item instance
func (k KeyID) Get() *items.Item {
	return items.NewItem("Key ID", fmt.Sprintf("0x%X", uint64(k)), "")
}

func (k KeyID) String() string {
	return k.Get().String()
}

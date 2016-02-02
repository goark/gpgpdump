package values

import (
	"strconv"

	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

//Version - information version
type Version struct {
	ver byte
	cur byte
}

//NewVersion returns new Version instance
func NewVersion(ver, cur byte) Version {
	return Version{ver: ver, cur: cur}
}

// IsOld return true if old version
func (v Version) IsOld() bool {
	return v.ver < v.cur
}

// IsNew return true if new version
func (v Version) IsNew() bool {
	return v.ver == v.cur
}

// Get returns Item instance
func (v Version) Get() *items.Item {
	var note string
	switch true {
	case v.IsOld():
		note = "old"
	case v.IsNew():
		note = "new"
	default:
		note = "unknown"
	}
	return items.NewItem("Version", strconv.Itoa(int(v.ver)), note)
}

// PubVer is Public-Key Packet Version
func PubVer(ver byte) Version {
	return NewVersion(ver, 4)
}

// SigVer is Signiture Packet Version
func SigVer(ver byte) Version {
	return NewVersion(ver, 4)
}

// OneSigVer is One-Pass Signature Packet Version
func OneSigVer(ver byte) Version {
	return NewVersion(ver, 3)
}

// PubSessKeyVer is Public-Key Encrypted Session Key Packet Version
func PubSessKeyVer(ver byte) Version {
	return NewVersion(ver, 3)
}

// SymSessKeyVer is Symmetric-Key Encrypted Session Key Packet Version
func SymSessKeyVer(ver byte) Version {
	return NewVersion(ver, 4)
}

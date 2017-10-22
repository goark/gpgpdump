package values

import (
	"strconv"

	"github.com/spiegel-im-spiegel/gpgpdump/info"
)

//Version - information version
type Version struct {
	ver byte //version number
	cur byte //current version in RFC4880
}

//NewVersion returns new Version instance
func NewVersion(ver, cur byte) *Version {
	return &Version{ver: ver, cur: cur}
}

//IsOld return true if old version
func (v *Version) IsOld() bool {
	if v == nil {
		return false
	}
	return v.ver < v.cur
}

//IsNew return true if new version
func (v *Version) IsNew() bool {
	if v == nil {
		return false
	}
	return v.ver == v.cur
}

//IsUnknown return true if unknown version
func (v *Version) IsUnknown() bool {
	return !v.IsOld() && !v.IsNew()
}

//ToItem returns Item instance
func (v *Version) ToItem() *info.Item {
	if v == nil {
		return nil
	}
	var note string
	switch true {
	case v.IsOld():
		note = "old"
	case v.IsNew():
		note = "new"
	default:
		note = "unknown"
	}
	return info.NewItem(
		info.Name("Version"),
		info.Value(v.String()),
		info.Note(note),
	)
}

func (v *Version) String() string {
	return strconv.Itoa(int(v.ver))
}

// PubVer is Public-Key Packet Version
func PubVer(ver byte) *Version {
	return NewVersion(ver, 4)
}

// SigVer is Signiture Packet Version
func SigVer(ver byte) *Version {
	return NewVersion(ver, 4)
}

// OneSigVer is One-Pass Signature Packet Version
func OneSigVer(ver byte) *Version {
	return NewVersion(ver, 3)
}

// PubSessKeyVer is Public-Key Encrypted Session Key Packet Version
func PubSessKeyVer(ver byte) *Version {
	return NewVersion(ver, 3)
}

// SymSessKeyVer is Symmetric-Key Encrypted Session Key Packet Version
func SymSessKeyVer(ver byte) *Version {
	return NewVersion(ver, 4)
}

/* Copyright 2016 Spiegel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

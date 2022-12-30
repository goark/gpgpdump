package values

import (
	"strconv"

	"github.com/goark/gpgpdump/parse/result"
)

// Version - information version
type Version struct {
	ver   byte //version number
	cur   byte //current version in RFC4880
	draft byte //draft version in RFC4880bis
}

// NewVersion returns new Version instance
func NewVersion(ver, cur, draft byte) *Version {
	return &Version{ver: ver, cur: cur, draft: draft}
}

// Number returns number of version
func (v *Version) Number() int {
	if v == nil {
		return 0
	}
	return int(v.ver)
}

// IsOld return true if old version
func (v *Version) IsOld() bool {
	if v == nil {
		return false
	}
	return v.ver < v.cur
}

// IsCurrent return true if current version
func (v *Version) IsCurrent() bool {
	if v == nil {
		return false
	}
	return v.ver == v.cur
}

// IsDraft return true if draft version
func (v *Version) IsDraft() bool {
	if v == nil {
		return false
	}
	if v.draft == 0 {
		return false
	}
	return v.ver == v.draft
}

// IsUnknown return true if unknown version
func (v *Version) IsUnknown() bool {
	return !v.IsOld() && !v.IsCurrent() && !v.IsDraft()
}

// ToItem returns Item instance
func (v *Version) ToItem(dumpFlag bool) *result.Item {
	if v == nil {
		return nil
	}
	var note string
	switch true {
	case v.IsOld():
		note = "old"
	case v.IsCurrent():
		note = "current"
	case v.IsDraft():
		note = "draft"
	default:
		note = "unknown"
	}
	return result.NewItem(
		result.Name("Version"),
		result.Value(v.String()),
		result.Note(note),
		result.DumpStr(DumpByteString(v.ver, dumpFlag)),
	)
}

func (v *Version) String() string {
	return strconv.Itoa(int(v.ver))
}

// PubVer is Public-Key Packet Version
func PubVer(ver byte) *Version {
	return NewVersion(ver, 4, 5)
}

// SigVer is Signiture Packet Version
func SigVer(ver byte) *Version {
	return NewVersion(ver, 4, 5)
}

// OneSigVer is One-Pass Signature Packet Version
func OneSigVer(ver byte) *Version {
	return NewVersion(ver, 3, 5)
}

// PubSessKeyVer is Public-Key Encrypted Session Key Packet Version
func PubSessKeyVer(ver byte) *Version {
	return NewVersion(ver, 3, 5)
}

// SymSessKeyVer is Symmetric-Key Encrypted Session Key Packet Version
func SymSessKeyVer(ver byte) *Version {
	return NewVersion(ver, 4, 5)
}

// AEADPacketVer is AEAD Encrypted Data Packet Version
func AEADVer(ver byte) *Version {
	return NewVersion(ver, 1, 0)
}

/* Copyright 2016-2022 Spiegel
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

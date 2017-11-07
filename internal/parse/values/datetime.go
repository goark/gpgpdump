package values

import (
	"fmt"
	"time"

	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

//Expire - Expiration Time
type Expire struct {
	name  string
	buf   []byte
	start int64
	utc   bool
}

//NewExpire returns new Expire instance
func NewExpire(name string, buf []byte, start int64, utc bool) *Expire {
	return &Expire{name: name, buf: buf, start: start, utc: utc}
}

// Get returns Item instance
func (e Expire) Get() *items.Item {
	exp := int64(Octets2Int(e.buf))
	end := ""
	if e.start > 0 {
		end = RFC3339(e.start+exp, e.utc)
	}
	return items.NewItem(e.name, fmt.Sprintf("%v days after", float64(exp)/86400.0), end, DumpByte(e.buf))
}

//SigExpire returns new Expire instance
func SigExpire(buf []byte, start int64, utc bool) *Expire {
	return NewExpire("Signature Expiration Time", buf, start, utc)
}

//KeyExpire returns new Expire instance
func KeyExpire(buf []byte, start int64, utc bool) *Expire {
	return NewExpire("Key Expiration Time", buf, start, utc)
}

//UNIXTime - UNIX Time
type UNIXTime struct {
	name string
	buf  []byte
	unix int64
	utc  bool
}

//NewUNIXTime returns new UNIXTime instance
func NewUNIXTime(name string, buf []byte, utc bool) *UNIXTime {
	return &UNIXTime{name: name, buf: buf, unix: int64(Octets2Int(buf)), utc: utc}
}

// Unix returns UNIX Time
func (u *UNIXTime) Unix() int64 {
	return u.unix
}

// RFC3339 returns string with RFC3339 format
func (u *UNIXTime) RFC3339() string {
	return RFC3339(u.unix, u.utc)
}

// Get returns Item instance
func (u *UNIXTime) Get() *items.Item {
	return items.NewItem(u.name, u.RFC3339(), "", DumpByte(u.buf))
}

// RFC3339 returns string with RFC3339 format
func RFC3339(unix int64, utc bool) string {
	t := time.Unix(unix, 0)
	if utc {
		t = t.In(time.UTC)
	}
	return t.Format(time.RFC3339)
}

//FileTime returns UNIXTime instance for Modification time of a file
func FileTime(buf []byte, utc bool) *UNIXTime {
	return NewUNIXTime("Modification time of a file", buf, utc)
}

//PubKeyTime returns UNIXTime instance for Public key creation time
func PubKeyTime(buf []byte, utc bool) *UNIXTime {
	return NewUNIXTime("Public key creation time", buf, utc)
}

//SigTime returns UNIXTime instance for Signature creation time
func SigTime(buf []byte, utc bool) *UNIXTime {
	return NewUNIXTime("Signature creation time", buf, utc)
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

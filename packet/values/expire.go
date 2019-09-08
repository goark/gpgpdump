package values

import (
	"encoding/binary"
	"fmt"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
)

//Expire class is Expiration Time
type Expire struct {
	start *DateTime
	day   []byte
}

//NewExpire returns new Expire instance
func NewExpire(r *reader.Reader, start *DateTime) (*Expire, error) {
	day, err := r.ReadBytes(4)
	if err != nil {
		return nil, errs.Wrap(err, "illegal body of Expire value")
	}
	return &Expire{start: start, day: day}, nil
}

//ToItem returns Item instance
func (e *Expire) ToItem(name string, dumpFlag bool) *info.Item {
	if e == nil {
		return nil
	}
	exp := binary.BigEndian.Uint32(e.day)
	start := e.start.UnixTime()
	var endDay string
	if start > 0 {
		endDay = unixtime2RFC3339(start+exp, e.start.utcFlag)
	}
	return info.NewItem(
		info.Name(name),
		info.Value(fmt.Sprintf("%v days after", float64(exp)/86400.0)),
		info.Note(endDay),
		info.DumpStr(DumpBytes(e.day, dumpFlag).String()),
	)
}

//SigExpireItem returns new Expire instance
func SigExpireItem(exp *Expire, dumpFlag bool) *info.Item {
	return exp.ToItem("Signature Expiration Time", dumpFlag)
}

//KeyExpireItem returns new Expire instance
func KeyExpireItem(exp *Expire, dumpFlag bool) *info.Item {
	return exp.ToItem("Key Expiration Time", dumpFlag)
}

/* Copyright 2016-2019 Spiegel
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

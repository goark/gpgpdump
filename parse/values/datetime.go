package values

import (
	"encoding/binary"
	"time"

	"github.com/goark/errs"

	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
)

//DateTime class as UNIX time
type DateTime struct {
	tm      []byte
	utcFlag bool
}

//NewDateTime returns DateTime instance
func NewDateTime(r *reader.Reader, utcFlag bool) (*DateTime, error) {
	tm, err := r.ReadBytes(4)
	if err != nil {
		return nil, errs.New("illegal body of DateTime value", errs.WithCause(err))
	}
	return &DateTime{tm: tm, utcFlag: utcFlag}, nil
}

//ToItem returns Item instance
func (dt *DateTime) ToItem(name string, dumpFlag bool) *result.Item {
	if dt == nil {
		return nil
	}
	return result.NewItem(
		result.Name(name),
		result.Value(dt.RFC3339()),
		result.DumpStr(DumpBytes(dt.tm, dumpFlag).String()),
	)
}

//UnixTime returns UNIX time value from DateTime
func (dt *DateTime) UnixTime() uint32 {
	if dt == nil {
		return 0
	}
	return binary.BigEndian.Uint32(dt.tm)
}

//IsZero returns true if UNIX time is zero value
func (dt *DateTime) IsZero() bool {
	if dt == nil {
		return true
	}
	return dt.UnixTime() == 0
}

//RFC3339 returns string with RFC3339 format
func (dt *DateTime) RFC3339() string {
	if dt == nil {
		return ""
	}
	return unixtime2RFC3339(dt.UnixTime(), dt.utcFlag)
}
func unixtime2RFC3339(ut uint32, utcFlag bool) string {
	t := time.Unix(int64(ut), 0)
	if utcFlag {
		t = t.In(time.UTC)
	}
	return t.Format(time.RFC3339)
}

//FileTimeItem returns UNIXTime instance for Modification time of a file
func FileTimeItem(dt *DateTime, dumpFlag bool) *result.Item {
	name := "Creation time"
	if dt.IsZero() {
		return result.NewItem(
			result.Name(name),
			result.Value("null"),
			result.DumpStr(DumpBytes(dt.tm, dumpFlag).String()),
		)
	}
	return dt.ToItem(name, dumpFlag)
}

//PubKeyTimeItem returns UNIXTime instance for Public key creation time
func PubKeyTimeItem(dt *DateTime, dumpFlag bool) *result.Item {
	return dt.ToItem("Public key creation time", dumpFlag)
}

//SigTimeItem returns UNIXTime instance for Signature creation time
func SigTimeItem(dt *DateTime, dumpFlag bool) *result.Item {
	return dt.ToItem("Signature creation time", dumpFlag)
}

/* Copyright 2016-2020 Spiegel
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

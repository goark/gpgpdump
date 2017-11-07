package values

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
)

//Dumpdata - raw data for dump
type Dumpdata struct {
	reader *reader.Reader
	dump   bool
}

func (d *Dumpdata) String() string {
	if !d.dump {
		return ""
	}
	return d.reader.DumpString(0)
}

//Dump returns Dumpdata instance
func Dump(r *reader.Reader, f bool) *Dumpdata {
	return &Dumpdata{reader: r, dump: f}
}

//DumpBytes returns Dumpdata instance
func DumpBytes(data []byte, f bool) *Dumpdata {
	return Dump(reader.NewReader(data), f)
}

//DumpByteString returns string
func DumpByteString(data byte, f bool) string {
	if !f {
		return ""
	}
	return fmt.Sprintf("%02x", data)
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

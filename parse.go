package gpgpdump

import (
	"io"
	"io/ioutil"

	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/options"
	"github.com/spiegel-im-spiegel/gpgpdump/packet"
)

//var (
//	ErrNoData = errors.New("cannot parse data")
//)

//Parse returns packet info.
func Parse(r io.Reader, o *options.Options) (*info.Info, error) {
	data, err := ioutil.ReadAll(r) //buffering to []byte
	if err != nil {
		return nil, err
	}
	reader, err := packet.NewReader(data, o)
	if err != nil {
		return nil, err
	}
	return reader.Parse()
}

/* Copyright 2017 Spiegel
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

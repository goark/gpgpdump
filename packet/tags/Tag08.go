package tags

import (
	"bytes"
	"compress/bzip2"
	"compress/flate"
	"compress/zlib"
	"io"

	"github.com/pkg/errors"
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

// tag08 class for Compressed Data Packet
type Tag08 struct {
	*tagInfo
	data io.Reader
}

//newTag08 return tag08 instance
func newTag08(cxt *context.Context, tag values.TagID, body []byte) Tags {
	info := &tagInfo{cxt: cxt, tag: tag, reader: reader.New(body)}
	return &Tag08{tagInfo: info, data: nil}
}

// Parse parsing Compressed Data Packet
func (t *Tag08) Parse() (*info.Item, error) {
	rootInfo := t.tag.ToItem(t.reader, t.cxt.Debug())
	compID, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, err
	}
	cid := values.CompID(compID)
	rootInfo.Add(cid.ToItem(t.cxt.Debug()))

	if t.reader.Rest() > 0 {
		var err error
		switch compID {
		case 1: //zip <RFC1951>
			t.data, err = t.extractZip()
		case 2: //zlib <RFC1950>
			t.data, err = t.extractZLib()
		case 3: //bzip2
			t.data, err = t.extractBzip2()
		default:
			rootInfo.Add(values.RawData(t.reader, "Compressed data", t.cxt.Debug()))
		}
		return rootInfo, err
	}
	return rootInfo, nil
}

func (t *Tag08) Reader() io.Reader {
	return t.data
}

func (t *Tag08) extractZip() (io.Reader, error) {
	zd, err := t.reader.Read2EOF()
	if err != nil {
		return nil, errors.Wrap(err, "error in tag08.extractZip() function")
	}
	zr := flate.NewReader(bytes.NewReader(zd))
	buf := new(bytes.Buffer)
	io.Copy(buf, zr)
	return buf, nil
}

func (t *Tag08) extractZLib() (io.Reader, error) {
	zd, err := t.reader.Read2EOF()
	if err != nil {
		return nil, errors.Wrap(err, "error in tag08.extractZip() function")
	}
	zr, err := zlib.NewReader(bytes.NewReader(zd))
	if err != nil {
		return nil, errors.Wrap(err, "error in tag08.extractZip() function")
	}
	buf := new(bytes.Buffer)
	io.Copy(buf, zr)
	return buf, nil
}

func (t *Tag08) extractBzip2() (io.Reader, error) {
	zd, err := t.reader.Read2EOF()
	if err != nil {
		return nil, errors.Wrap(err, "error in tag08.extractZip() function")
	}
	zr := bzip2.NewReader(bytes.NewReader(zd))
	buf := new(bytes.Buffer)
	io.Copy(buf, zr)
	return buf, nil
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

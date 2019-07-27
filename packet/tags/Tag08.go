package tags

import (
	"bytes"
	"compress/bzip2"
	"compress/flate"
	"compress/zlib"
	"io"
	"io/ioutil"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

//Tag08 class for Compressed Data Packet
type Tag08 struct {
	tagInfo
	data io.Reader
}

//newTag08 return tag08 instance
func newTag08(cxt *context.Context, tag values.TagID, body []byte) Tags {
	return &Tag08{tagInfo: tagInfo{cxt: cxt, tag: tag, reader: reader.New(body)}, data: ioutil.NopCloser(bytes.NewReader(nil))}
}

// Parse parsing Compressed Data Packet
func (t *Tag08) Parse() (*info.Item, error) {
	rootInfo := t.ToItem()
	compID, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.Wrapf(err, "illegal compID in parsing tag %d", int(t.tag))
	}
	cid := values.CompID(compID)
	rootInfo.Add(cid.ToItem(t.cxt.Debug()))

	if t.reader.Rest() > 0 {
		rootInfo.Add(values.RawData(t.reader, "Compressed data", t.cxt.Debug()))
		var err error
		switch compID {
		case 0: //Uncompressed
			var zd []byte
			zd, err = t.reader.Read2EOF()
			if err != nil {
				return rootInfo, errs.Wrapf(err, "illegal compressed data in parsing tag %d", int(t.tag))
			}
			t.data = bytes.NewReader(zd)
		case 1: //zip <RFC1951>
			t.data, err = t.extractZip()
		case 2: //zlib <RFC1950>
			t.data, err = t.extractZLib()
		case 3: //bzip2
			t.data, err = t.extractBzip2()
		default:
		}
		return rootInfo, errs.Wrapf(err, "error in parsing tag %d", int(t.tag))
	}
	return rootInfo, nil
}

//Reader returns io.Reader of compressed data
func (t *Tag08) Reader() io.Reader {
	return t.data
}

func (t *Tag08) extractZip() (io.Reader, error) {
	zd, err := t.reader.Read2EOF()
	if err != nil {
		return ioutil.NopCloser(bytes.NewReader(nil)), errs.Wrap(err, "error in extract data (zip)")
	}
	zr := flate.NewReader(bytes.NewReader(zd))
	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, zr)
	return buf, errs.Wrap(err, "error in extract data (zip)")
}

func (t *Tag08) extractZLib() (io.Reader, error) {
	zd, err := t.reader.Read2EOF()
	if err != nil {
		return ioutil.NopCloser(bytes.NewReader(nil)), errs.Wrap(err, "error in extract data (zlib)")
	}
	zr, err := zlib.NewReader(bytes.NewReader(zd))
	if err != nil {
		return ioutil.NopCloser(bytes.NewReader(nil)), errs.Wrap(err, "error in extract data (zlib)")
	}
	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, zr)
	return buf, err
}

func (t *Tag08) extractBzip2() (io.Reader, error) {
	zd, err := t.reader.Read2EOF()
	if err != nil {
		return ioutil.NopCloser(bytes.NewReader(nil)), errs.Wrap(err, "error in extract data (bzip2)")
	}
	zr := bzip2.NewReader(bytes.NewReader(zd))
	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, zr)
	return buf, errs.Wrap(err, "error in extract data (bzip2)")
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

package tags

import (
	"bytes"
	"compress/bzip2"
	"compress/flate"
	"compress/zlib"
	"io"
	"strings"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/ecode"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/context"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/result"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/values"
)

//Tag08 class for Compressed Data Packet
type Tag08 struct {
	tagInfo
	data io.Reader
}

//newTag08 return tag08 instance
func newTag08(cxt *context.Context, tag values.TagID, body []byte) Tags {
	return &Tag08{tagInfo: tagInfo{cxt: cxt, tag: tag, reader: reader.New(body)}, data: io.NopCloser(bytes.NewReader(nil))}
}

// Parse parsing Compressed Data Packet
func (t *Tag08) Parse() (*result.Item, error) {
	rootInfo := t.ToItem()
	compID, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal compID", errs.WithCause(err))
	}
	cid := values.CompID(compID)
	rootInfo.Add(cid.ToItem(t.cxt.Debug()))

	if t.reader.Rest() > 0 {
		item := values.RawData(t.reader, "Compressed data", t.cxt.Debug())
		var err error
		switch compID {
		case 0: //Uncompressed
			var zd []byte
			zd, err = t.reader.Read2EOF()
			if err != nil {
				rootInfo.Add(item)
				return rootInfo, errs.New("illegal compressed data", errs.WithCause(err))
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
		if err != nil && errs.Is(err, ecode.ErrTooLarge) {
			item.Value = strings.Join([]string{"<", err.Error(), ">"}, "")
			err = nil
		}
		rootInfo.Add(item)
		return rootInfo, errs.Wrap(err)
	}
	return rootInfo, nil
}

//Reader returns io.Reader of compressed data
func (t *Tag08) Reader() io.Reader {
	return t.data
}

const maxDecompressionDataSize = 1024 * 1024 * 1024 //1GB

func (t *Tag08) extractZip() (io.Reader, error) {
	zd, err := t.reader.Read2EOF()
	if err != nil {
		return nil, errs.Wrap(err)
	}
	zr := flate.NewReader(bytes.NewReader(zd))
	defer zr.Close()
	return copyFrom(zr)
}

func (t *Tag08) extractZLib() (io.Reader, error) {
	zd, err := t.reader.Read2EOF()
	if err != nil {
		return nil, errs.Wrap(err)
	}
	zr, err := zlib.NewReader(bytes.NewReader(zd))
	if err != nil {
		return nil, errs.Wrap(err)
	}
	defer zr.Close()
	return copyFrom(zr)
}

func (t *Tag08) extractBzip2() (io.Reader, error) {
	zd, err := t.reader.Read2EOF()
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return copyFrom(bzip2.NewReader(bytes.NewReader(zd)))
}

func copyFrom(r io.Reader) (io.Reader, error) {
	buf := &bytes.Buffer{}
	if _, err := io.CopyN(buf, r, maxDecompressionDataSize); err != nil {
		if errs.Is(err, io.EOF) {
			return buf, nil
		}
		return nil, errs.Wrap(err)
	}
	return nil, errs.Wrap(ecode.ErrTooLarge)
}

/* Copyright 2016-2021 Spiegel
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

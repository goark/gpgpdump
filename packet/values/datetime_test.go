package values

import (
	"io"
	"testing"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
)

var (
	ut      = []byte{0x36, 0x5e, 0x72, 0x6e}
	rfc3339 = "1998-11-27T09:35:42Z"
)

func TestRFC3339(t *testing.T) {
	dt, err := NewDateTime(reader.New(ut), true) //UTC
	if err != nil {
		t.Errorf("NewDateTime() = \"%+v\", want nil error.", err)
	}
	res := dt.RFC3339()
	if res != rfc3339 {
		t.Errorf("NewDateTime() = \"%v\", want \"%v\".", res, rfc3339)
	}
}

func TestRFC3339Err(t *testing.T) {
	ut2 := []byte{0x36}
	_, err := NewDateTime(reader.New(ut2), true) //UTC
	if !errs.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("NewDateTime() = \"%+v\", want \"%+v\".", err, io.ErrUnexpectedEOF)
	}
}

func TestRFC3339NIl1(t *testing.T) {
	dt := (*DateTime)(nil)
	res := dt.RFC3339()
	if res != "" {
		t.Errorf("RFC3339() = \"%v\", want \"\".", res)
	}
}

func TestDateTimeNIl1(t *testing.T) {
	dt := (*DateTime)(nil)
	if dt.UnixTime() != 0 {
		t.Errorf("UnixTime() = %v, want 0.", dt.UnixTime())
	}
}

func TestToItemNIl1(t *testing.T) {
	dt := (*DateTime)(nil)
	if dt.ToItem("name", true) != nil {
		t.Error("ToItem() is not nil, want nil.")
	}
}

func TestFileTimeItem(t *testing.T) {
	name := "Modification time of a file"
	dt, err := NewDateTime(reader.New(ut), true) //UTC
	if err != nil {
		t.Errorf("NewDateTime() = \"%+v\", want nil error.", err)
	}
	itm := FileTimeItem(dt, true)
	if itm.Name != name {
		t.Errorf("FileTimeItem() = \"%v\", want \"%v\".", itm.Name, name)
	}
	if itm.Value != rfc3339 {
		t.Errorf("FileTimeItem() = \"%v\", want \"%v\".", itm.Value, rfc3339)
	}
}

func TestPubKeyTimeItem(t *testing.T) {
	name := "Public key creation time"
	dt, err := NewDateTime(reader.New(ut), true) //UTC
	if err != nil {
		t.Errorf("NewDateTime() = \"%+v\", want nil error.", err)
	}
	itm := PubKeyTimeItem(dt, true)
	if itm.Name != name {
		t.Errorf("FileTimeItem() = \"%v\", want \"%v\".", itm.Name, name)
	}
	if itm.Value != rfc3339 {
		t.Errorf("FileTimeItem() = \"%v\", want \"%v\".", itm.Value, rfc3339)
	}
}

func TestSigTimeItem(t *testing.T) {
	name := "Signature creation time"
	dt, err := NewDateTime(reader.New(ut), true) //UTC
	if err != nil {
		t.Errorf("NewDateTime() = \"%+v\", want nil error.", err)
	}
	itm := SigTimeItem(dt, true)
	if itm.Name != name {
		t.Errorf("FileTimeItem() = \"%v\", want \"%v\".", itm.Name, name)
	}
	if itm.Value != rfc3339 {
		t.Errorf("FileTimeItem() = \"%v\", want \"%v\".", itm.Value, rfc3339)
	}
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

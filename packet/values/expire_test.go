package values

import (
	"fmt"
	"io"
	"testing"

	"github.com/spiegel-im-spiegel/gpgpdump/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
)

var (
	start = []byte{0x36, 0x5e, 0x72, 0x6e} //1998-11-27T09:35:42Z
	day   = []byte{0x00, 0x09, 0x3a, 0x80} //604800sec
)

func TestExpireErr(t *testing.T) {
	dt, _ := NewDateTime(reader.New(start), true) //UTC
	//name := "Signature Expiration Time"
	//days := "7 days after"
	//rfc3339 := "1998-12-04T09:35:42Z"
	//dump := "00 09 3a 80"
	dayErr := []byte{0x00}
	_, err := NewExpire(reader.New(dayErr), dt)
	if !errs.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("NewExpire() = \"%+v\", want \"%+v\".", err, io.ErrUnexpectedEOF)
	} else {
		fmt.Printf("Info: %+v\n", err)
	}
}

func TestExpireNil(t *testing.T) {
	exp := (*Expire)(nil)
	itm := exp.ToItem("name", true)
	if itm != nil {
		t.Error("ToItem() not nil, want nil.")
	}
}

func TestSigExpireItem(t *testing.T) {
	dt, _ := NewDateTime(reader.New(start), true) //UTC
	name := "Signature Expiration Time"
	days := "7 days after"
	rfc3339 := "1998-12-04T09:35:42Z"
	dump := "00 09 3a 80"
	exp, err := NewExpire(reader.New(day), dt)
	if err != nil {
		t.Errorf("NewDateTime() = \"%+v\", want nil error.", err)
	}
	itm := SigExpireItem(exp, true)
	if itm.Name != name {
		t.Errorf("SigExpireItem() = \"%v\", want \"%v\".", itm.Name, name)
	}
	if itm.Value != days {
		t.Errorf("SigExpireItem() = \"%v\", want \"%v\".", itm.Value, days)
	}
	if itm.Note != rfc3339 {
		t.Errorf("SigExpireItem() = \"%v\", want \"%v\".", itm.Note, rfc3339)
	}
	if itm.Dump != dump {
		t.Errorf("SigExpireItem() = \"%v\", want \"%v\".", itm.Dump, dump)
	}
}

func TestKeyExpireItem(t *testing.T) {
	dt, _ := NewDateTime(reader.New(start), true) //UTC
	name := "Key Expiration Time"
	days := "7 days after"
	rfc3339 := "1998-12-04T09:35:42Z"
	dump := "00 09 3a 80"
	exp, err := NewExpire(reader.New(day), dt)
	if err != nil {
		t.Errorf("NewDateTime() = \"%+v\", want nil error.", err)
	}
	itm := KeyExpireItem(exp, true)
	if itm.Name != name {
		t.Errorf("SigExpireItem() = \"%v\", want \"%v\".", itm.Name, name)
	}
	if itm.Value != days {
		t.Errorf("SigExpireItem() = \"%v\", want \"%v\".", itm.Value, days)
	}
	if itm.Note != rfc3339 {
		t.Errorf("SigExpireItem() = \"%v\", want \"%v\".", itm.Note, rfc3339)
	}
	if itm.Dump != dump {
		t.Errorf("SigExpireItem() = \"%v\", want \"%v\".", itm.Dump, dump)
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

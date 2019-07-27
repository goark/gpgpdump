package reader

import (
	"bytes"
	"io"
	"testing"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/ecode"
)

var buffer = []byte{0x01, 0x02, 0x03, 0x04}

func TestReadBytes(t *testing.T) {
	var res = []byte{0x01, 0x02}
	v, err := New(buffer).ReadBytes(2)
	if err != nil {
		t.Errorf("ReadBytes() = \"%v\", want nil.", err)
	}
	if len(v) != 2 || v[0] != res[0] || v[1] != res[1] {
		t.Errorf("ReadBytes() = %v, want %v.", v, res)
	}
}

func TestReadBytes0(t *testing.T) {
	v, err := New(buffer).ReadBytes(0)
	if err != nil {
		t.Errorf("ReadBytes() = \"%v\", want nil.", err)
	}
	if v != nil {
		t.Errorf("ReadBytes() = %v, want nil.", v)
	}
}

func TestReadBytesErr(t *testing.T) {
	_, err := New(buffer).ReadBytes(5)
	if !errs.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("ReadBytes() = \"%v\", want \"%v\".", err, io.ErrUnexpectedEOF)
	}
}

func TestRead(t *testing.T) {
	var res = []byte{0x01, 0x02}
	buf := make([]byte, 2)
	s, err := New(buffer).Read(buf)
	if err != nil {
		t.Errorf("Read() = \"%v\", want nil.", err)
	}
	if s != 2 {
		t.Errorf("Read() size = %v, want %v.", s, 2)
	}
	if buf[0] != res[0] || buf[1] != res[1] {
		t.Errorf("Read() = %v, want %v.", buf, res)
	}
}

func TestReadErr(t *testing.T) {
	buf := make([]byte, 5)
	if _, err := New(buffer).Read(buf); !errs.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("Read() = \"%v\", want \"%v\".", err, io.ErrUnexpectedEOF)
	}
}

func TestReadAt(t *testing.T) {
	var res = []byte{0x03, 0x04}
	reader := New(buffer)
	buf := make([]byte, 2)
	s, err := reader.ReadAt(buf, 2)
	if err != nil {
		t.Errorf("ReadAt() = \"%v\", want nil.", err)
	}
	if s != 2 {
		t.Errorf("ReadAt() size = %v, want %v.", s, 2)
	}
	if buf[0] != res[0] || buf[1] != res[1] {
		t.Errorf("ReadAt() = %v, want %v.", buf, res)
	}
	if _, err = reader.ReadAt(buf, 4); !errs.Is(err, io.EOF) {
		t.Errorf("ReadAt() = \"%v\", want \"%v\".", err, io.EOF)
	}
	off, err := reader.Seek(-2, io.SeekCurrent)
	if err != nil {
		t.Errorf("Seek() = \"%v\", want nil.", err)
	}
	if off != 2 {
		t.Errorf("Seek() = \"%v\", want 2.", off)
	}
	if reader.Rest() != 2 {
		t.Errorf("Rest() = \"%v\", want 2.", reader.Rest())
	}
	s, err = reader.ReadAt(buf, 2)
	if err != nil {
		t.Errorf("ReadAt() = \"%v\", want nil.", err)
	}
	if s != 2 {
		t.Errorf("ReadAt() size = %v, want %v.", s, 2)
	}
	if buf[0] != res[0] || buf[1] != res[1] {
		t.Errorf("ReadAt() = %v, want %v.", buf, res)
	}
}

func TestWriteTo(t *testing.T) {
	var res = []byte{0x01, 0x02, 0x03, 0x04}
	reader := New(buffer)
	buf := new(bytes.Buffer)
	s, err := reader.WriteTo(buf)
	if err != nil {
		t.Errorf("WriteTo() = \"%v\", want nil.", err)
	}
	if s != 4 {
		t.Errorf("WriteTo() size = %v, want %v.", s, 4)
	}
	v := buf.Bytes()
	if !bytes.Equal(res, v) {
		t.Errorf("WriteTo() = %v, want %v.", v, res)
	}
}

func TestSeekFromEnd(t *testing.T) {
	reader := New(buffer)
	off, err := reader.Seek(0, io.SeekEnd)
	if err != nil {
		t.Errorf("Seek() = \"%v\", want nil.", err)
	}
	if off != 4 {
		t.Errorf("Seek() = \"%v\", want 4.", off)
	}
	_, err = reader.ReadByte()
	if err == nil {
		t.Errorf("Seek() and ReadByte() = nil error, want \"%v\".", io.EOF)
	}
}

func TestSeekErr(t *testing.T) {
	reader := New(buffer)
	_, err := reader.Seek(0, 3)
	if !errs.Is(err, ecode.ErrInvalidWhence) {
		t.Errorf("ReadByte() = \"%v\", want \"%v\".", err, ecode.ErrInvalidWhence)
	}
}

func TestRead2EOF(t *testing.T) {
	var res = []byte{0x01, 0x02, 0x03, 0x04}
	reader := New(buffer)
	v, err := reader.Read2EOF()
	if err != nil {
		t.Errorf("Read2EOF() = \"%v\", want nil.", err)
	}
	if !bytes.Equal(res, v) {
		t.Errorf("Read2EOF() = %v, want %v.", v, res)
	}
	if _, err := reader.Read2EOF(); !errs.Is(err, io.EOF) {
		t.Errorf("Read2EOF() = \"%v\", want \"%v\".", err, io.EOF)
	}
}

func TestReadByte(t *testing.T) {
	var res = []byte{0x01, 0x02, 0x03, 0x04}
	reader := New(buffer)
	for i := 0; i < 4; i++ {
		b, err := reader.ReadByte()
		if err != nil {
			t.Errorf("ReadByte() = \"%v\", want nil.", err)
		}
		if b != res[i] {
			t.Errorf("ReadByte() = %v, want %v.", b, res[i])
		}
	}
	if _, err := reader.ReadByte(); !errs.Is(err, io.EOF) {
		t.Errorf("ReadByte() = \"%v\", want \"%v\".", err, io.EOF)
	}
}

func TestGetBody(t *testing.T) {
	var res = []byte{0x01, 0x02, 0x03, 0x04}
	reader := New(buffer)
	v := reader.GetBody()
	if !bytes.Equal(res, v) {
		t.Errorf("Read2EOF() = %v, want %v.", v, res)
	}
}

func TestDump(t *testing.T) {
	reader := New(buffer)
	d := reader.DumpString(2)
	if d != "03 04" {
		t.Errorf("DumpString() = \"%v\", want \"03 04\".", d)
	}
	d = reader.DumpString(4)
	if d != "" {
		t.Errorf("DumpString() = \"%v\", want \"\".", d)
	}
	b, err := reader.ReadByte()
	if err != nil {
		t.Errorf("ReadByte() = \"%v\", want nil.", err)
	}
	if b != 0x01 {
		t.Errorf("ReadByte() = %v, want %v.", b, 0x01)
	}
}

/* Copyright 2017-2019 Spiegel
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

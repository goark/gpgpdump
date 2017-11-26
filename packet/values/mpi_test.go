package values

import (
	"io"
	"testing"

	"github.com/pkg/errors"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
)

var (
	data1 = []byte{0x00, 0x9f, 0x6f, 0x0b, 0x0c, 0x39, 0x68, 0x64, 0xf2, 0xff, 0xea, 0x63, 0x80, 0xc6, 0x6c, 0x69, 0xaa, 0x3d, 0x4e, 0x3c, 0x46, 0x54}
	data2 = []byte{0x00, 0x9f, 0x6f}
	data3 = []byte{0x00}
)

var (
	dump1 = "6f 0b 0c 39 68 64 f2 ff ea 63 80 c6 6c 69 aa 3d 4e 3c 46 54"
)

func TestNewMPINoName(t *testing.T) {
	reader := reader.New(data1)
	m, err := NewMPI(reader)
	if err != nil {
		t.Errorf("NewMPI() = \"%v\", want nil error.", err)
	}
	i := m.ToItem("", true)
	if i.Name != "Multi-precision integer" {
		t.Errorf("MPI.Name = \"%v\", want \"Multi-precision integer\".", i.Name)
	}
	if i.Value != "" {
		t.Errorf("MPI.Value = \"%v\", want \"\".", i.Value)
	}
	if i.Note != "159 bits" {
		t.Errorf("MPI.Note = \"%v\", want \"159 bits\"", i.Note)
	}
	if i.Dump != dump1 {
		t.Errorf("MPI.Dump = \"%v\", want \"%s\".", i.Dump, dump1)
	}
}

func TestNewMPIandName(t *testing.T) {
	reader := reader.New(data1)
	m, err := NewMPI(reader)
	if err != nil {
		t.Errorf("NewMPI() = \"%v\", want nil error.", err)
	}
	i := m.ToItem("name", true)
	if i.Name != "name" {
		t.Errorf("MPI.Name = \"%v\", want \"name\".", i.Name)
	}
	if i.Value != "" {
		t.Errorf("MPI.Value = \"%v\", want \"\".", i.Value)
	}
	if i.Note != "159 bits" {
		t.Errorf("MPI.Note = \"%v\", want \"159 bits\"", i.Note)
	}
	if i.Dump != dump1 {
		t.Errorf("MPI.Dump = \"%v\", want \"%s\".", i.Dump, dump1)
	}
}

func TestNewMPIErr(t *testing.T) {
	reader := reader.New(data2)
	_, err := NewMPI(reader)
	if err != nil {
		if errors.Cause(err) != io.ErrUnexpectedEOF {
			t.Errorf("NewMPI = \"%v\", want \"%v\".", err, io.ErrUnexpectedEOF)
		}
	} else {
		t.Errorf("NewMPI = nil error, want \"%v\".", io.ErrUnexpectedEOF)
	}
}

func TestNewMPIErr2(t *testing.T) {
	reader := reader.New(data3)
	_, err := NewMPI(reader)
	if err != nil {
		if errors.Cause(err) != io.ErrUnexpectedEOF {
			t.Errorf("NewMPI = \"%v\", want \"%v\".", err, io.ErrUnexpectedEOF)
		}
	} else {
		t.Errorf("NewMPI = nil error, want \"%v\".", io.ErrUnexpectedEOF)
	}
}

func TestMPINil(t *testing.T) {
	mpi := (*MPI)(nil)
	if mpi.ToItem("", true) != nil {
		t.Error("MPI to Item: not nil, want nil.")
	}
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

package s2k

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
)

func TestS2Knil(t *testing.T) {
	opt := &options.Options{}
	var data = []byte{}
	reader := bytes.NewReader(data)
	s2k := New(opt, reader)
	i, err := s2k.Get()
	if err == nil {
		t.Error("S2K err = nil, not want nil.")
	} else {
		fmt.Println(err)
	}
	if i != nil {
		t.Error("S2K = not nil, want nil.")
	}
}

func TestSimpleS2K(t *testing.T) {
	opt := &options.Options{}
	var data = []byte{0x00, 0x08, 0xff, 0xff}
	reader := bytes.NewReader(data)
	s2k := New(opt, reader)
	i, err := s2k.Get()
	if err != nil {
		t.Errorf("S2K err = \"%v\", want nil.", err)
	} else {
		if i.Name != "String-to-Key (S2K) Algorithm" {
			t.Errorf("S2K.Name = \"%v\", want \"String-to-Key (S2K) Algorithm\".", i.Name)
		}
		if i.Value != "Simple S2K (s2k 0)" {
			t.Errorf("S2K.Value = \"%v\", want \"Simple S2K (s2k 0)\".", i.Value)
		}
		if i.Note != "" {
			t.Errorf("S2K.Note = \"%v\", want \"\"", i.Note)
		}
		if i.Dump != "" {
			t.Errorf("S2K.Dump = \"%v\", want \"\".", i.Dump)
		}
		if len(i.Item) != 1 {
			t.Errorf("S2K.Item count = %d, want 1.", len(i.Item))
		} else {
			hash := i.Item[0]
			if hash.Name != "Hash Algorithm" {
				t.Errorf("S2K.HashAlg.Name = \"%s\", want \"Hash Algorithm\".", hash.Name)
			}
			if hash.Value != "SHA256 (hash 8)" {
				t.Errorf("S2K.HashAlg.Value = \"%s\", want \"SHA256 (hash 8)\".", hash.Value)
			}
			if hash.Note != "" {
				t.Errorf("S2K.HashAlg.Note = \"%s\", want \"\"", hash.Note)
			}
			if hash.Dump != "" {
				t.Errorf("S2K.HashAlg.Dump = \"%s\", want \"\".", hash.Dump)
			}
		}
		if s2k.Left() != 2 {
			t.Errorf("S2K.Left() = %d, want 2.", s2k.Left())
		}
		if !s2k.HasIV() {
			t.Errorf("S2K.HasIV() = %v, want true", s2k.HasIV())
		}
	}
}

func TestSimpleS2Kerr(t *testing.T) {
	opt := &options.Options{}
	var data = []byte{0x00}
	reader := bytes.NewReader(data)
	s2k := New(opt, reader)
	i, err := s2k.Get()
	if err == nil {
		t.Error("S2K err = nil, not want nil.")
	} else {
		fmt.Println(err)
	}
	if i == nil {
		t.Error("S2K = nil, not want nil.")
	} else {
		if i.Name != "String-to-Key (S2K) Algorithm" {
			t.Errorf("S2K.Name = \"%v\", want \"String-to-Key (S2K) Algorithm\".", i.Name)
		}
		if i.Value != "Simple S2K (s2k 0)" {
			t.Errorf("S2K.Value = \"%v\", want \"Simple S2K (s2k 0)\".", i.Value)
		}
		if i.Note != "" {
			t.Errorf("S2K.Note = \"%v\", want \"\"", i.Note)
		}
		if i.Dump != "" {
			t.Errorf("S2K.Dump = \"%v\", want \"\".", i.Dump)
		}
		if len(i.Item) != 0 {
			t.Errorf("S2K.Item count = %d, want 0.", len(i.Item))
		}
	}
}

func TestSaltedS2K(t *testing.T) {
	opt := &options.Options{}
	var data = []byte{0x01, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xff, 0xff}
	saltDump := "01 02 03 04 05 06 07 08"
	reader := bytes.NewReader(data)
	s2k := New(opt, reader)
	i, err := s2k.Get()
	if err != nil {
		t.Errorf("S2K err = \"%v\", want nil.", err)
	} else {
		if i.Name != "String-to-Key (S2K) Algorithm" {
			t.Errorf("S2K.Name = \"%v\", want \"String-to-Key (S2K) Algorithm\".", i.Name)
		}
		if i.Value != "Salted S2K (s2k 1)" {
			t.Errorf("S2K.Value = \"%v\", want \"Salted S2K (s2k 1)\".", i.Value)
		}
		if i.Note != "" {
			t.Errorf("S2K.Note = \"%v\", want \"\"", i.Note)
		}
		if i.Dump != "" {
			t.Errorf("S2K.Dump = \"%v\", want \"\".", i.Dump)
		}
		if len(i.Item) != 2 {
			t.Errorf("S2K.Item count = %d, want 2.", len(i.Item))
		} else {
			hash := i.Item[0]
			if hash.Name != "Hash Algorithm" {
				t.Errorf("S2K.HashAlg.Name = \"%s\", want \"Hash Algorithm\".", hash.Name)
			}
			if hash.Value != "SHA256 (hash 8)" {
				t.Errorf("S2K.HashAlg.Value = \"%s\", want \"SHA256 (hash 8)\".", hash.Value)
			}
			if hash.Note != "" {
				t.Errorf("S2K.HashAlg.Note = \"%s\", want \"\"", hash.Note)
			}
			if hash.Dump != "" {
				t.Errorf("S2K.HashAlg.Dump = \"%s\", want \"\".", hash.Dump)
			}
			salt := i.Item[1]
			if salt.Name != "Salt" {
				t.Errorf("S2K.Salt.Name = \"%s\", want \"Salt\".", salt.Name)
			}
			if salt.Value != "" {
				t.Errorf("S2K.Salt.Value = \"%s\", want \"\".", salt.Value)
			}
			if salt.Note != "" {
				t.Errorf("S2K.Salt.Note = \"%s\", want \"\"", salt.Note)
			}
			if salt.Dump != saltDump {
				t.Errorf("S2K.Salt.Dump = \"%s\", want \"%s\".", salt.Dump, saltDump)
			}
		}
		if s2k.Left() != 2 {
			t.Errorf("S2K.Left() = %d, want 2.", s2k.Left())
		}
		if !s2k.HasIV() {
			t.Errorf("S2K.HasIV() = %v, want true", s2k.HasIV())
		}
	}
}

func TestSaltedS2Kerr(t *testing.T) {
	opt := &options.Options{}
	var data = []byte{0x01, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	reader := bytes.NewReader(data)
	s2k := New(opt, reader)
	i, err := s2k.Get()
	if err == nil {
		t.Error("S2K err = nil, not want nil.")
	} else {
		fmt.Println(err)
	}
	if i == nil {
		t.Error("S2K = nil, not want nil.")
	} else {
		if i.Value != "Salted S2K (s2k 1)" {
			t.Errorf("S2K.Value = \"%v\", want \"Salted S2K (s2k 1)\".", i.Value)
		}
		if i.Note != "" {
			t.Errorf("S2K.Note = \"%v\", want \"\"", i.Note)
		}
		if i.Dump != "" {
			t.Errorf("S2K.Dump = \"%v\", want \"\".", i.Dump)
		}
		if len(i.Item) != 1 {
			t.Errorf("S2K.Item count = %d, want 1.", len(i.Item))
		} else {
			hash := i.Item[0]
			if hash.Name != "Hash Algorithm" {
				t.Errorf("S2K.HashAlg.Name = \"%s\", want \"Hash Algorithm\".", hash.Name)
			}
			if hash.Value != "SHA256 (hash 8)" {
				t.Errorf("S2K.HashAlg.Value = \"%s\", want \"SHA256 (hash 8)\".", hash.Value)
			}
			if hash.Note != "" {
				t.Errorf("S2K.HashAlg.Note = \"%s\", want \"\"", hash.Note)
			}
			if hash.Dump != "" {
				t.Errorf("S2K.HashAlg.Dump = \"%s\", want \"\".", hash.Dump)
			}
		}
	}
}

func TestIteratedSaltedS2K(t *testing.T) {
	opt := &options.Options{}
	var data = []byte{0x03, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xc3, 0xff, 0xff}
	saltDump := "01 02 03 04 05 06 07 08"
	reader := bytes.NewReader(data)
	s2k := New(opt, reader)
	i, err := s2k.Get()
	if err != nil {
		t.Errorf("S2K err = \"%v\", want nil.", err)
	} else {
		if i.Name != "String-to-Key (S2K) Algorithm" {
			t.Errorf("S2K.Name = \"%v\", want \"String-to-Key (S2K) Algorithm\".", i.Name)
		}
		if i.Value != "Iterated and Salted S2K (s2k 3)" {
			t.Errorf("S2K.Value = \"%v\", want \"Iterated and Salted S2K (s2k 3)\".", i.Value)
		}
		if i.Note != "" {
			t.Errorf("S2K.Note = \"%v\", want \"\"", i.Note)
		}
		if i.Dump != "" {
			t.Errorf("S2K.Dump = \"%v\", want \"\".", i.Dump)
		}
		if len(i.Item) != 3 {
			t.Errorf("S2K.Item count = %d, want 3.", len(i.Item))
		} else {
			hash := i.Item[0]
			if hash.Name != "Hash Algorithm" {
				t.Errorf("S2K.HashAlg.Name = \"%s\", want \"Hash Algorithm\".", hash.Name)
			}
			if hash.Value != "SHA256 (hash 8)" {
				t.Errorf("S2K.HashAlg.Value = \"%s\", want \"SHA256 (hash 8)\".", hash.Value)
			}
			if hash.Note != "" {
				t.Errorf("S2K.HashAlg.Note = \"%s\", want \"\"", hash.Note)
			}
			if hash.Dump != "" {
				t.Errorf("S2K.HashAlg.Dump = \"%s\", want \"\".", hash.Dump)
			}
			salt := i.Item[1]
			if salt.Name != "Salt" {
				t.Errorf("S2K.Salt.Name = \"%s\", want \"Salt\".", salt.Name)
			}
			if salt.Value != "" {
				t.Errorf("S2K.Salt.Value = \"%s\", want \"\".", salt.Value)
			}
			if salt.Note != "" {
				t.Errorf("S2K.Salt.Note = \"%s\", want \"\"", salt.Note)
			}
			if salt.Dump != saltDump {
				t.Errorf("S2K.Salt.Dump = \"%s\", want \"%s\".", salt.Dump, saltDump)
			}
			count := i.Item[2]
			if count.Name != "Count" {
				t.Errorf("S2K.Count.Name = \"%s\", want \"Count\".", count.Name)
			}
			if count.Value != "4980736" {
				t.Errorf("S2K.Count.Value = \"%s\", want \"4980736\".", count.Value)
			}
			if count.Note != "coded: 0xc3" {
				t.Errorf("S2K.Count.Note = \"%s\", want \"coded: 0xc3\"", count.Note)
			}
			if count.Dump != "" {
				t.Errorf("S2K.Count.Dump = \"%s\", want \"\".", salt.Dump)
			}
		}
		if s2k.Left() != 2 {
			t.Errorf("S2K.Left() = %d, want 2.", s2k.Left())
		}
		if !s2k.HasIV() {
			t.Errorf("S2K.HasIV() = %v, want true", s2k.HasIV())
		}
	}
}

func TestIteratedSaltedS2Kerr(t *testing.T) {
	opt := &options.Options{}
	var data = []byte{0x03, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	saltDump := "01 02 03 04 05 06 07 08"
	reader := bytes.NewReader(data)
	s2k := New(opt, reader)
	i, err := s2k.Get()
	if err == nil {
		t.Error("S2K err = nil, not want nil.")
	} else {
		fmt.Println(err)
	}
	if i == nil {
		t.Error("S2K = nil, not want nil.")
	} else {
		if i.Name != "String-to-Key (S2K) Algorithm" {
			t.Errorf("S2K.Name = \"%v\", want \"String-to-Key (S2K) Algorithm\".", i.Name)
		}
		if i.Value != "Iterated and Salted S2K (s2k 3)" {
			t.Errorf("S2K.Value = \"%v\", want \"Iterated and Salted S2K (s2k 3)\".", i.Value)
		}
		if i.Note != "" {
			t.Errorf("S2K.Note = \"%v\", want \"\"", i.Note)
		}
		if i.Dump != "" {
			t.Errorf("S2K.Dump = \"%v\", want \"\".", i.Dump)
		}
		if len(i.Item) != 2 {
			t.Errorf("S2K.Item count = %d, want 2.", len(i.Item))
		} else {
			hash := i.Item[0]
			if hash.Name != "Hash Algorithm" {
				t.Errorf("S2K.HashAlg.Name = \"%s\", want \"Hash Algorithm\".", hash.Name)
			}
			if hash.Value != "SHA256 (hash 8)" {
				t.Errorf("S2K.HashAlg.Value = \"%s\", want \"SHA256 (hash 8)\".", hash.Value)
			}
			if hash.Note != "" {
				t.Errorf("S2K.HashAlg.Note = \"%s\", want \"\"", hash.Note)
			}
			if hash.Dump != "" {
				t.Errorf("S2K.HashAlg.Dump = \"%s\", want \"\".", hash.Dump)
			}
			salt := i.Item[1]
			if salt.Name != "Salt" {
				t.Errorf("S2K.Salt.Name = \"%s\", want \"Salt\".", salt.Name)
			}
			if salt.Value != "" {
				t.Errorf("S2K.Salt.Value = \"%s\", want \"\".", salt.Value)
			}
			if salt.Note != "" {
				t.Errorf("S2K.Salt.Note = \"%s\", want \"\"", salt.Note)
			}
			if salt.Dump != saltDump {
				t.Errorf("S2K.Salt.Dump = \"%s\", want \"%s\".", salt.Dump, saltDump)
			}
		}
	}
}

func TestUnknownS2K(t *testing.T) {
	opt := &options.Options{}
	var data = []byte{0x02, 0xff, 0xff}
	reader := bytes.NewReader(data)
	s2k := New(opt, reader)
	i, err := s2k.Get()
	if err != nil {
		t.Errorf("S2K err = \"%v\", want nil.", err)
	} else {
		if i.Name != "String-to-Key (S2K) Algorithm" {
			t.Errorf("S2K.Name = \"%v\", want \"String-to-Key (S2K) Algorithm\".", i.Name)
		}
		if i.Value != "Reserved (s2k 2)" {
			t.Errorf("S2K.Value = \"%v\", want \"Reserved (s2k 2)\".", i.Value)
		}
		if i.Note != "" {
			t.Errorf("S2K.Note = \"%v\", want \"\"", i.Note)
		}
		if i.Dump != "" {
			t.Errorf("S2K.Dump = \"%v\", want \"\".", i.Dump)
		}
		if len(i.Item) != 0 {
			t.Errorf("S2K.Item count = %d, want 1.", len(i.Item))
		}
		if s2k.Left() != 2 {
			t.Errorf("S2K.Left() = %d, want 2.", s2k.Left())
		}
		if !s2k.HasIV() {
			t.Errorf("S2K.HasIV() = %v, want true", s2k.HasIV())
		}
	}
}

func TestExpS2K(t *testing.T) {
	opt := &options.Options{}
	var data = []byte{101, 0xff, 0xff, 0xff, 0xff}
	reader := bytes.NewReader(data)
	s2k := New(opt, reader)
	i, err := s2k.Get()
	if err != nil {
		t.Errorf("S2K err = \"%v\", want nil.", err)
	} else {
		if i.Name != "String-to-Key (S2K) Algorithm" {
			t.Errorf("S2K.Name = \"%v\", want \"String-to-Key (S2K) Algorithm\".", i.Name)
		}
		if i.Value != "Private/Experimental algorithm (s2k 101)" {
			t.Errorf("S2K.Value = \"%v\", want \"Private/Experimental algorithm (s2k 101)\".", i.Value)
		}
		if i.Note != "" {
			t.Errorf("S2K.Note = \"%v\", want \"\"", i.Note)
		}
		if i.Dump != "" {
			t.Errorf("S2K.Dump = \"%v\", want \"\".", i.Dump)
		}
		if len(i.Item) != 0 {
			t.Errorf("S2K.Item count = %d, want 0.", len(i.Item))
		}
		if s2k.Left() != 4 {
			t.Errorf("S2K.Left() = %d, want 2.", s2k.Left())
		}
		if !s2k.HasIV() {
			t.Errorf("S2K.HasIV() = %v, want true", s2k.HasIV())
		}
	}
}

func TestExpS2Kgnu1(t *testing.T) {
	opt := &options.Options{}
	var data = []byte{101, 'G', 'N', 'U', 0x01, 0xff, 0xff}
	reader := bytes.NewReader(data)
	s2k := New(opt, reader)
	i, err := s2k.Get()
	if err != nil {
		t.Errorf("S2K err = \"%v\", want nil.", err)
	} else {
		if i.Name != "String-to-Key (S2K) Algorithm" {
			t.Errorf("S2K.Name = \"%v\", want \"String-to-Key (S2K) Algorithm\".", i.Name)
		}
		if i.Value != "Private/Experimental algorithm (s2k 101)" {
			t.Errorf("S2K.Value = \"%v\", want \"Private/Experimental algorithm (s2k 101)\".", i.Value)
		}
		if i.Note != "" {
			t.Errorf("S2K.Note = \"%v\", want \"\"", i.Note)
		}
		if i.Dump != "" {
			t.Errorf("S2K.Dump = \"%v\", want \"\".", i.Dump)
		}
		if len(i.Item) != 1 {
			t.Errorf("S2K.Item count = %d, want 0.", len(i.Item))
		} else {
			gnu := i.Item[0]
			if gnu.Name != "GNU-divert-to-card" {
				t.Errorf("S2K.Gnu.Name = \"%s\", want \"Hash Algorithm\".", gnu.Name)
			}
			if gnu.Value != "Extension Number 1001" {
				t.Errorf("S2K.Gnu.Value = \"%s\", want \"Extension Number 1001\".", gnu.Value)
			}
			if gnu.Note != "" {
				t.Errorf("S2K.Gnu.Note = \"%s\", want \"\"", gnu.Note)
			}
			if gnu.Dump != "" {
				t.Errorf("S2K.Gnu.Dump = \"%s\", want \"\".", gnu.Dump)
			}
			if len(gnu.Item) != 0 {
				t.Errorf("S2K.Gnu.Item count = %d, want 0.", len(i.Item))
			}
		}
		if s2k.Left() != 2 {
			t.Errorf("S2K.Left() = %d, want 2.", s2k.Left())
		}
		if s2k.HasIV() {
			t.Errorf("S2K.HasIV() = %v, want false", s2k.HasIV())
		}
	}
}

func TestExpS2Kgnu2(t *testing.T) {
	opt := &options.Options{}
	var data = []byte{101, 'G', 'N', 'U', 0x02, 0x04, 0x01, 0x02, 0x03, 0x04, 0xff, 0xff}
	snDumo := "01 02 03 04"
	reader := bytes.NewReader(data)
	s2k := New(opt, reader)
	i, err := s2k.Get()
	if err != nil {
		t.Errorf("S2K err = \"%v\", want nil.", err)
	} else {
		if i.Name != "String-to-Key (S2K) Algorithm" {
			t.Errorf("S2K.Name = \"%v\", want \"String-to-Key (S2K) Algorithm\".", i.Name)
		}
		if i.Value != "Private/Experimental algorithm (s2k 101)" {
			t.Errorf("S2K.Value = \"%v\", want \"Private/Experimental algorithm (s2k 101)\".", i.Value)
		}
		if i.Note != "" {
			t.Errorf("S2K.Note = \"%v\", want \"\"", i.Note)
		}
		if i.Dump != "" {
			t.Errorf("S2K.Dump = \"%v\", want \"\".", i.Dump)
		}
		if len(i.Item) != 1 {
			t.Errorf("S2K.Item count = %d, want 0.", len(i.Item))
		} else {
			gnu := i.Item[0]
			if gnu.Name != "GNU-divert-to-card" {
				t.Errorf("S2K.Gnu.Name = \"%s\", want \"Hash Algorithm\".", gnu.Name)
			}
			if gnu.Value != "Extension Number 1002" {
				t.Errorf("S2K.Gnu.Value = \"%s\", want \"Extension Number 1002\".", gnu.Value)
			}
			if gnu.Note != "" {
				t.Errorf("S2K.Gnu.Note = \"%s\", want \"\"", gnu.Note)
			}
			if gnu.Dump != "" {
				t.Errorf("S2K.Gnu.Dump = \"%s\", want \"\".", gnu.Dump)
			}
			if len(gnu.Item) != 1 {
				t.Errorf("S2K.Gnu.Item count = %d, want 1.", len(i.Item))
			} else {
				sn := gnu.Item[0]
				if sn.Name != "Serial Number" {
					t.Errorf("S2K.Gnu.Num,Name = \"%s\", want \"Serial Number\".", sn.Name)
				}
				if sn.Value != "" {
					t.Errorf("S2K.Gnu.Num,Value = \"%s\", want \"\".", sn.Value)
				}
				if sn.Note != "" {
					t.Errorf("S2K.Gnu.Num,Note = \"%s\", want \"\"", sn.Note)
				}
				if sn.Dump != snDumo {
					t.Errorf("S2K.Gnu.Num,Dump = \"%s\", want \"%s\".", sn.Dump, snDumo)
				}
			}
		}
		if s2k.Left() != 2 {
			t.Errorf("S2K.Left() = %d, want 2.", s2k.Left())
		}
		if s2k.HasIV() {
			t.Errorf("S2K.HasIV() = %v, want false", s2k.HasIV())
		}
	}
}

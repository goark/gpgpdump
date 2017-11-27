package s2k

import (
	"fmt"
	"testing"

	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
)

func TestS2KNil(t *testing.T) {
	parent := info.NewItem()
	s2k := (*S2K)(nil)
	if err := s2k.Parse(parent, true); err != nil {
		t.Errorf("S2K err = \"%v\", want nil.", err)
	}
	if parent.Items != nil {
		t.Error("S2K = not nil, want nil.")
	}
}

func TestS2KEmpty(t *testing.T) {
	parent := info.NewItem()
	var data = []byte{}
	s2k := New(reader.New(data))
	if err := s2k.Parse(parent, true); err == nil {
		t.Error("S2K err = nil, not want nil.")
	} else {
		fmt.Println("info:", err)
	}
	if parent.Items != nil {
		t.Error("S2K = not nil, want nil.")
	}
}

func TestSimpleS2K(t *testing.T) {
	parent := info.NewItem()
	var data = []byte{0x00, 0x08, 0xff, 0xff}
	reader := reader.New(data)
	s2k := New(reader)
	if err := s2k.Parse(parent, true); err != nil {
		t.Errorf("S2K err = \"%v\", want nil.", err)
	} else if len(parent.Items) != 1 {
		t.Errorf("S2K.Item count = %d, want 1.", len(parent.Items))
	} else {
		i := parent.Items[0]
		if i.Name != "String-to-Key (S2K) Algorithm" {
			t.Errorf("S2K.Name = \"%v\", want \"String-to-Key (S2K) Algorithm\".", i.Name)
		}
		if i.Value != "Simple S2K (s2k 0)" {
			t.Errorf("S2K.Value = \"%v\", want \"Simple S2K (s2k 0)\".", i.Value)
		}
		if i.Note != "" {
			t.Errorf("S2K.Note = \"%v\", want \"\"", i.Note)
		}
		if i.Dump != "00" {
			t.Errorf("S2K.Dump = \"%v\", want \"00\".", i.Dump)
		}
		if len(i.Items) != 1 {
			t.Errorf("S2K.Item count = %d, want 1.", len(i.Items))
		} else {
			hash := i.Items[0]
			if hash.Name != "Hash Algorithm" {
				t.Errorf("S2K.HashAlg.Name = \"%s\", want \"Hash Algorithm\".", hash.Name)
			}
			if hash.Value != "SHA2-256 (hash 8)" {
				t.Errorf("S2K.HashAlg.Value = \"%s\", want \"SHA2-256 (hash 8)\".", hash.Value)
			}
			if hash.Note != "" {
				t.Errorf("S2K.HashAlg.Note = \"%s\", want \"\"", hash.Note)
			}
			if hash.Dump != "08" {
				t.Errorf("S2K.HashAlg.Dump = \"%s\", want \"08\".", hash.Dump)
			}
		}
		if reader.Rest() != 2 {
			t.Errorf("Rest = %d, want 2.", reader.Rest())
		}
		if !s2k.HasIV() {
			t.Errorf("S2K.HasIV() = %v, want true", s2k.HasIV())
		}
	}
}

func TestSimpleS2Kerr(t *testing.T) {
	parent := info.NewItem()
	var data = []byte{0x00}
	s2k := New(reader.New(data))
	if err := s2k.Parse(parent, true); err == nil {
		t.Error("S2K err = nil, not want nil.")
	} else {
		fmt.Println("info:", err)
	}
	if len(parent.Items) != 1 {
		t.Errorf("S2K.Item count = %d, want 1.", len(parent.Items))
	} else {
		i := parent.Items[0]
		if i.Name != "String-to-Key (S2K) Algorithm" {
			t.Errorf("S2K.Name = \"%v\", want \"String-to-Key (S2K) Algorithm\".", i.Name)
		}
		if i.Value != "Simple S2K (s2k 0)" {
			t.Errorf("S2K.Value = \"%v\", want \"Simple S2K (s2k 0)\".", i.Value)
		}
		if i.Note != "" {
			t.Errorf("S2K.Note = \"%v\", want \"\"", i.Note)
		}
		if i.Dump != "00" {
			t.Errorf("S2K.Dump = \"%v\", want \"00\".", i.Dump)
		}
		if len(i.Items) != 0 {
			t.Errorf("S2K.Item count = %d, want 0.", len(i.Items))
		}
	}
}

func TestSaltedS2K(t *testing.T) {
	parent := info.NewItem()
	var data = []byte{0x01, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xff, 0xff}
	saltDump := "01 02 03 04 05 06 07 08"
	reader := reader.New(data)
	s2k := New(reader)
	if err := s2k.Parse(parent, true); err != nil {
		t.Errorf("S2K err = \"%v\", want nil.", err)
	} else if len(parent.Items) != 1 {
		t.Errorf("S2K.Item count = %d, want 1.", len(parent.Items))
	} else {
		i := parent.Items[0]
		if i.Name != "String-to-Key (S2K) Algorithm" {
			t.Errorf("S2K.Name = \"%v\", want \"String-to-Key (S2K) Algorithm\".", i.Name)
		}
		if i.Value != "Salted S2K (s2k 1)" {
			t.Errorf("S2K.Value = \"%v\", want \"Salted S2K (s2k 1)\".", i.Value)
		}
		if i.Note != "" {
			t.Errorf("S2K.Note = \"%v\", want \"\"", i.Note)
		}
		if i.Dump != "01" {
			t.Errorf("S2K.Dump = \"%v\", want \"01\".", i.Dump)
		}
		if len(i.Items) != 2 {
			t.Errorf("S2K.Item count = %d, want 2.", len(i.Items))
		} else {
			hash := i.Items[0]
			if hash.Name != "Hash Algorithm" {
				t.Errorf("S2K.HashAlg.Name = \"%s\", want \"Hash Algorithm\".", hash.Name)
			}
			if hash.Value != "SHA2-256 (hash 8)" {
				t.Errorf("S2K.HashAlg.Value = \"%s\", want \"SHA2-256 (hash 8)\".", hash.Value)
			}
			if hash.Note != "" {
				t.Errorf("S2K.HashAlg.Note = \"%s\", want \"\"", hash.Note)
			}
			if hash.Dump != "08" {
				t.Errorf("S2K.HashAlg.Dump = \"%s\", want \"08\".", hash.Dump)
			}
			salt := i.Items[1]
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
		if reader.Rest() != 2 {
			t.Errorf("Rest = %d, want 2.", reader.Rest())
		}
		if !s2k.HasIV() {
			t.Errorf("S2K.HasIV() = %v, want true", s2k.HasIV())
		}
	}
}

func TestSaltedS2Kerr(t *testing.T) {
	parent := info.NewItem()
	var data = []byte{0x01, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	reader := reader.New(data)
	s2k := New(reader)
	if err := s2k.Parse(parent, true); err == nil {
		t.Error("S2K err = nil, not want nil.")
	} else {
		fmt.Println("info:", err)
	}
	if len(parent.Items) != 1 {
		t.Errorf("S2K.Item count = %d, want 1.", len(parent.Items))
	} else {
		i := parent.Items[0]
		if i.Value != "Salted S2K (s2k 1)" {
			t.Errorf("S2K.Value = \"%v\", want \"Salted S2K (s2k 1)\".", i.Value)
		}
		if i.Note != "" {
			t.Errorf("S2K.Note = \"%v\", want \"\"", i.Note)
		}
		if i.Dump != "01" {
			t.Errorf("S2K.Dump = \"%v\", want \"01\".", i.Dump)
		}
		if len(i.Items) != 1 {
			t.Errorf("S2K.Item count = %d, want 1.", len(i.Items))
		} else {
			hash := i.Items[0]
			if hash.Name != "Hash Algorithm" {
				t.Errorf("S2K.HashAlg.Name = \"%s\", want \"Hash Algorithm\".", hash.Name)
			}
			if hash.Value != "SHA2-256 (hash 8)" {
				t.Errorf("S2K.HashAlg.Value = \"%s\", want \"SHA2-256 (hash 8)\".", hash.Value)
			}
			if hash.Note != "" {
				t.Errorf("S2K.HashAlg.Note = \"%s\", want \"\"", hash.Note)
			}
			if hash.Dump != "08" {
				t.Errorf("S2K.HashAlg.Dump = \"%s\", want \"08\".", hash.Dump)
			}
		}
	}
}

func TestIteratedSaltedS2K(t *testing.T) {
	parent := info.NewItem()
	var data = []byte{0x03, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xc3, 0xff, 0xff}
	saltDump := "01 02 03 04 05 06 07 08"
	reader := reader.New(data)
	s2k := New(reader)
	if err := s2k.Parse(parent, true); err != nil {
		t.Errorf("S2K err = \"%v\", want nil.", err)
	} else if len(parent.Items) != 1 {
		t.Errorf("S2K.Item count = %d, want 1.", len(parent.Items))
	} else {
		i := parent.Items[0]
		if i.Name != "String-to-Key (S2K) Algorithm" {
			t.Errorf("S2K.Name = \"%v\", want \"String-to-Key (S2K) Algorithm\".", i.Name)
		}
		if i.Value != "Iterated and Salted S2K (s2k 3)" {
			t.Errorf("S2K.Value = \"%v\", want \"Iterated and Salted S2K (s2k 3)\".", i.Value)
		}
		if i.Note != "" {
			t.Errorf("S2K.Note = \"%v\", want \"\"", i.Note)
		}
		if i.Dump != "03" {
			t.Errorf("S2K.Dump = \"%v\", want \"03\".", i.Dump)
		}
		if len(i.Items) != 3 {
			t.Errorf("S2K.Item count = %d, want 3.", len(i.Items))
		} else {
			hash := i.Items[0]
			if hash.Name != "Hash Algorithm" {
				t.Errorf("S2K.HashAlg.Name = \"%s\", want \"Hash Algorithm\".", hash.Name)
			}
			if hash.Value != "SHA2-256 (hash 8)" {
				t.Errorf("S2K.HashAlg.Value = \"%s\", want \"SHA2-256 (hash 8)\".", hash.Value)
			}
			if hash.Note != "" {
				t.Errorf("S2K.HashAlg.Note = \"%s\", want \"\"", hash.Note)
			}
			if hash.Dump != "08" {
				t.Errorf("S2K.HashAlg.Dump = \"%s\", want \"08\".", hash.Dump)
			}
			salt := i.Items[1]
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
			count := i.Items[2]
			if count.Name != "Count" {
				t.Errorf("S2K.Count.Name = \"%s\", want \"Count\".", count.Name)
			}
			if count.Value != "4980736" {
				t.Errorf("S2K.Count.Value = \"%s\", want \"4980736\".", count.Value)
			}
			if count.Note != "" {
				t.Errorf("S2K.Count.Note = \"%s\", want \"\"", count.Note)
			}
			if count.Dump != "c3" {
				t.Errorf("S2K.Count.Dump = \"%s\", want \"c3\".", salt.Dump)
			}
		}
		if reader.Rest() != 2 {
			t.Errorf("Rest = %d, want 2.", reader.Rest())
		}
		if !s2k.HasIV() {
			t.Errorf("S2K.HasIV() = %v, want true", s2k.HasIV())
		}
	}
}

func TestIteratedSaltedS2Kerr(t *testing.T) {
	parent := info.NewItem()
	var data = []byte{0x03, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	saltDump := "01 02 03 04 05 06 07 08"
	reader := reader.New(data)
	s2k := New(reader)
	if err := s2k.Parse(parent, true); err == nil {
		t.Error("S2K err = nil, not want nil.")
	} else {
		fmt.Println("info:", err)
	}
	if len(parent.Items) != 1 {
		t.Errorf("S2K.Item count = %d, want 1.", len(parent.Items))
	} else {
		i := parent.Items[0]
		if i.Name != "String-to-Key (S2K) Algorithm" {
			t.Errorf("S2K.Name = \"%v\", want \"String-to-Key (S2K) Algorithm\".", i.Name)
		}
		if i.Value != "Iterated and Salted S2K (s2k 3)" {
			t.Errorf("S2K.Value = \"%v\", want \"Iterated and Salted S2K (s2k 3)\".", i.Value)
		}
		if i.Note != "" {
			t.Errorf("S2K.Note = \"%v\", want \"\"", i.Note)
		}
		if i.Dump != "03" {
			t.Errorf("S2K.Dump = \"%v\", want \"03\".", i.Dump)
		}
		if len(i.Items) != 2 {
			t.Errorf("S2K.Item count = %d, want 2.", len(i.Items))
		} else {
			hash := i.Items[0]
			if hash.Name != "Hash Algorithm" {
				t.Errorf("S2K.HashAlg.Name = \"%s\", want \"Hash Algorithm\".", hash.Name)
			}
			if hash.Value != "SHA2-256 (hash 8)" {
				t.Errorf("S2K.HashAlg.Value = \"%s\", want \"SHA2-256 (hash 8)\".", hash.Value)
			}
			if hash.Note != "" {
				t.Errorf("S2K.HashAlg.Note = \"%s\", want \"\"", hash.Note)
			}
			if hash.Dump != "08" {
				t.Errorf("S2K.HashAlg.Dump = \"%s\", want \"08\".", hash.Dump)
			}
			salt := i.Items[1]
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
	parent := info.NewItem()
	var data = []byte{0x02, 0xff, 0xff}
	reader := reader.New(data)
	s2k := New(reader)
	if err := s2k.Parse(parent, true); err != nil {
		t.Errorf("S2K err = \"%v\", want nil.", err)
	} else if len(parent.Items) != 1 {
		t.Errorf("S2K.Item count = %d, want 1.", len(parent.Items))
	} else {
		i := parent.Items[0]
		if i.Name != "String-to-Key (S2K) Algorithm" {
			t.Errorf("S2K.Name = \"%v\", want \"String-to-Key (S2K) Algorithm\".", i.Name)
		}
		if i.Value != "Reserved (s2k 2)" {
			t.Errorf("S2K.Value = \"%v\", want \"Reserved (s2k 2)\".", i.Value)
		}
		if i.Note != "" {
			t.Errorf("S2K.Note = \"%v\", want \"\"", i.Note)
		}
		if i.Dump != "02" {
			t.Errorf("S2K.Dump = \"%v\", want \"02\".", i.Dump)
		}
		if len(i.Items) != 0 {
			t.Errorf("S2K.Item count = %d, want 1.", len(i.Items))
		}
		if reader.Rest() != 2 {
			t.Errorf("Rest = %d, want 2.", reader.Rest())
		}
		if !s2k.HasIV() {
			t.Errorf("S2K.HasIV() = %v, want true", s2k.HasIV())
		}
	}
}

func TestExpS2K(t *testing.T) {
	parent := info.NewItem()
	var data = []byte{101, 0xff, 0xff, 0xff, 0xff}
	reader := reader.New(data)
	s2k := New(reader)
	if err := s2k.Parse(parent, true); err != nil {
		t.Errorf("S2K err = \"%v\", want nil.", err)
	} else if len(parent.Items) != 1 {
		t.Errorf("S2K.Item count = %d, want 1.", len(parent.Items))
	} else {
		i := parent.Items[0]
		if i.Name != "String-to-Key (S2K) Algorithm" {
			t.Errorf("S2K.Name = \"%v\", want \"String-to-Key (S2K) Algorithm\".", i.Name)
		}
		if i.Value != "Private/Experimental algorithm (s2k 101)" {
			t.Errorf("S2K.Value = \"%v\", want \"Private/Experimental algorithm (s2k 101)\".", i.Value)
		}
		if i.Note != "" {
			t.Errorf("S2K.Note = \"%v\", want \"\"", i.Note)
		}
		if i.Dump != "65" {
			t.Errorf("S2K.Dump = \"%v\", want \"65\".", i.Dump)
		}
		if len(i.Items) != 0 {
			t.Errorf("S2K.Item count = %d, want 0.", len(i.Items))
		}
		if reader.Rest() != 4 {
			t.Errorf("Rest = %d, want 4.", reader.Rest())
		}
		if !s2k.HasIV() {
			t.Errorf("S2K.HasIV() = %v, want true", s2k.HasIV())
		}
	}
}

func TestExpS2Kb(t *testing.T) {
	parent := info.NewItem()
	var data = []byte{101, 0xff, 0xff, 0xff}
	reader := reader.New(data)
	s2k := New(reader)
	if err := s2k.Parse(parent, true); err != nil {
		t.Errorf("S2K err = \"%v\", want nil.", err)
	} else if len(parent.Items) != 1 {
		t.Errorf("S2K.Item count = %d, want 1.", len(parent.Items))
	} else {
		i := parent.Items[0]
		if i.Name != "String-to-Key (S2K) Algorithm" {
			t.Errorf("S2K.Name = \"%v\", want \"String-to-Key (S2K) Algorithm\".", i.Name)
		}
		if i.Value != "Private/Experimental algorithm (s2k 101)" {
			t.Errorf("S2K.Value = \"%v\", want \"Private/Experimental algorithm (s2k 101)\".", i.Value)
		}
		if i.Note != "" {
			t.Errorf("S2K.Note = \"%v\", want \"\"", i.Note)
		}
		if i.Dump != "65" {
			t.Errorf("S2K.Dump = \"%v\", want \"65\".", i.Dump)
		}
		if len(i.Items) != 0 {
			t.Errorf("S2K.Item count = %d, want 0.", len(i.Items))
		}
		if reader.Rest() != 3 {
			t.Errorf("Rest = %d, want 4.", reader.Rest())
		}
		if !s2k.HasIV() {
			t.Errorf("S2K.HasIV() = %v, want true", s2k.HasIV())
		}
	}
}

func TestExpS2Kgnu1(t *testing.T) {
	parent := info.NewItem()
	var data = []byte{101, 'G', 'N', 'U', 0x01, 0xff, 0xff}
	reader := reader.New(data)
	s2k := New(reader)
	if err := s2k.Parse(parent, true); err != nil {
		t.Errorf("S2K err = \"%v\", want nil.", err)
	} else if len(parent.Items) != 1 {
		t.Errorf("S2K.Item count = %d, want 1.", len(parent.Items))
	} else {
		i := parent.Items[0]
		if i.Name != "String-to-Key (S2K) Algorithm" {
			t.Errorf("S2K.Name = \"%v\", want \"String-to-Key (S2K) Algorithm\".", i.Name)
		}
		if i.Value != "Private/Experimental algorithm (s2k 101)" {
			t.Errorf("S2K.Value = \"%v\", want \"Private/Experimental algorithm (s2k 101)\".", i.Value)
		}
		if i.Note != "" {
			t.Errorf("S2K.Note = \"%v\", want \"\"", i.Note)
		}
		if i.Dump != "65" {
			t.Errorf("S2K.Dump = \"%v\", want \"65\".", i.Dump)
		}
		if len(i.Items) != 1 {
			t.Errorf("S2K.Item count = %d, want 0.", len(i.Items))
		} else {
			gnu := i.Items[0]
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
			if len(gnu.Items) != 0 {
				t.Errorf("S2K.Gnu.Item count = %d, want 0.", len(i.Items))
			}
		}
		if reader.Rest() != 2 {
			t.Errorf("Rest = %d, want 2.", reader.Rest())
		}
		if s2k.HasIV() {
			t.Errorf("S2K.HasIV() = %v, want false", s2k.HasIV())
		}
	}
}

func TestExpS2Kgnu2(t *testing.T) {
	parent := info.NewItem()
	var data = []byte{101, 'G', 'N', 'U', 0x02, 0x04, 0x01, 0x02, 0x03, 0x04, 0xff, 0xff}
	snDumo := "01 02 03 04"
	reader := reader.New(data)
	s2k := New(reader)
	if err := s2k.Parse(parent, true); err != nil {
		t.Errorf("S2K err = \"%v\", want nil.", err)
	} else if len(parent.Items) != 1 {
		t.Errorf("S2K.Item count = %d, want 1.", len(parent.Items))
	} else {
		i := parent.Items[0]
		if i.Name != "String-to-Key (S2K) Algorithm" {
			t.Errorf("S2K.Name = \"%v\", want \"String-to-Key (S2K) Algorithm\".", i.Name)
		}
		if i.Value != "Private/Experimental algorithm (s2k 101)" {
			t.Errorf("S2K.Value = \"%v\", want \"Private/Experimental algorithm (s2k 101)\".", i.Value)
		}
		if i.Note != "" {
			t.Errorf("S2K.Note = \"%v\", want \"\"", i.Note)
		}
		if i.Dump != "65" {
			t.Errorf("S2K.Dump = \"%v\", want \"65\".", i.Dump)
		}
		if len(i.Items) != 1 {
			t.Errorf("S2K.Item count = %d, want 0.", len(i.Items))
		} else {
			gnu := i.Items[0]
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
			if len(gnu.Items) != 1 {
				t.Errorf("S2K.Gnu.Item count = %d, want 1.", len(i.Items))
			} else {
				sn := gnu.Items[0]
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
		if reader.Rest() != 2 {
			t.Errorf("Rest = %d, want 2.", reader.Rest())
		}
		if s2k.HasIV() {
			t.Errorf("S2K.HasIV() = %v, want false", s2k.HasIV())
		}
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

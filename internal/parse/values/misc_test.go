package values

import "testing"

func TestOctets2Int2(t *testing.T) {
	var data = []byte{0x01, 0x02}
	v := Octets2Int(data)
	if v != 0x0102 {
		t.Errorf("Octets2Int() = 0x%x, want 0x0102.", v)
	}
}

func TestOctets2Int4(t *testing.T) {
	var data = []byte{0x01, 0x02, 0x03, 0x04}
	v := Octets2Int(data)
	if v != 0x01020304 {
		t.Errorf("Octets2Int() = 0x%x, want 0x01020304.", v)
	}
}

func TestOctets2Int8(t *testing.T) {
	var data = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	v := Octets2Int(data)
	if v != 0x0102030405060708 {
		t.Errorf("Octets2Int() = 0x%x, want 0x0102030405060708.", v)
	}
}

func TestOctets2Int9(t *testing.T) {
	var data = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}
	v := Octets2Int(data)
	if v != 0 {
		t.Errorf("Octets2Int() = 0x%x, want 0.", v)
	}
}

func TestOctets2IntLE2(t *testing.T) {
	var data = []byte{0x01, 0x02}
	v := Octets2IntLE(data)
	if v != 0x0201 {
		t.Errorf("Octets2Int() = 0x%x, want 0x0201.", v)
	}
}

func TestOctets2IntLE4(t *testing.T) {
	var data = []byte{0x01, 0x02, 0x03, 0x04}
	v := Octets2IntLE(data)
	if v != 0 {
		t.Errorf("Octets2Int() = 0x%x, want 0.", v)
	}
}

package values

import "testing"

func TestRFC3339(t *testing.T) {
	ut := int64(0x365e726e)
	tt := RFC3339(ut, true)
	rfc3339 := "1998-11-27T09:35:42Z"
	if tt != rfc3339 {
		t.Errorf("RFC3339(0x%02x) = \"%v\", want \"%s\".", ut, tt, rfc3339)
	}
}

func TestUNIXTime(t *testing.T) {
	var ut = []byte{0x36, 0x5e, 0x72, 0x6e}
	utint := int64(0x365e726e)
	dump := "36 5e 72 6e"
	rfc3339 := "1998-11-27T09:35:42Z"
	v := NewUNIXTime("name1", ut, true)
	if v.RFC3339() != rfc3339 {
		t.Errorf("UNIXTime.RFC3339 = \"%v\", want \"%s\".", v.RFC3339(), rfc3339)
	}
	if v.Unix() != utint {
		t.Errorf("UNIXTime.Unix = 0x%02x, want 0x%02x.", v.RFC3339(), utint)
	}
	i := v.Get()
	if i.Name != "name1" {
		t.Errorf("UNIXTime.Name = \"%v\", want \"name1\".", i.Name)
	}
	if i.Value != rfc3339 {
		t.Errorf("UNIXTime.Value = \"%v\", want \"%s\".", i.Value, rfc3339)
	}
	if i.Note != "" {
		t.Errorf("UNIXTime.Note = \"%v\", want \"\"", i.Note)
	}
	if i.Dump != dump {
		t.Errorf("UNIXTime.Dump = \"%v\", want \"%s\".", i.Dump, dump)
	}
}

func TestFileTime(t *testing.T) {
	var ut = []byte{0x36, 0x5e, 0x72, 0x6e}
	dump := "36 5e 72 6e"
	rfc3339 := "1998-11-27T09:35:42Z"
	i := FileTime(ut, true).Get()
	if i.Name != "Modification time of a file" {
		t.Errorf("UNIXTime.Name = \"%v\", want \"Modification time of a file\".", i.Name)
	}
	if i.Value != rfc3339 {
		t.Errorf("UNIXTime.Value = \"%v\", want \"%s\".", i.Value, rfc3339)
	}
	if i.Note != "" {
		t.Errorf("UNIXTime.Note = \"%v\", want \"\"", i.Note)
	}
	if i.Dump != dump {
		t.Errorf("UNIXTime.Dump = \"%v\", want \"%s\".", i.Dump, dump)
	}
}

func TestPubKeyTime(t *testing.T) {
	var ut = []byte{0x36, 0x5e, 0x72, 0x6e}
	dump := "36 5e 72 6e"
	rfc3339 := "1998-11-27T09:35:42Z"
	i := PubKeyTime(ut, true).Get()
	if i.Name != "Public key creation time" {
		t.Errorf("UNIXTime.Name = \"%v\", want \"Public key creation time\".", i.Name)
	}
	if i.Value != rfc3339 {
		t.Errorf("UNIXTime.Value = \"%v\", want \"%s\".", i.Value, rfc3339)
	}
	if i.Note != "" {
		t.Errorf("UNIXTime.Note = \"%v\", want \"\"", i.Note)
	}
	if i.Dump != dump {
		t.Errorf("UNIXTime.Dump = \"%v\", want \"%s\".", i.Dump, dump)
	}
}

func TestSigTime(t *testing.T) {
	var ut = []byte{0x36, 0x5e, 0x72, 0x6e}
	dump := "36 5e 72 6e"
	rfc3339 := "1998-11-27T09:35:42Z"
	i := SigTime(ut, true).Get()
	if i.Name != "Signature creation time" {
		t.Errorf("UNIXTime.Name = \"%v\", want \"Signature creation time\".", i.Name)
	}
	if i.Value != rfc3339 {
		t.Errorf("UNIXTime.Value = \"%v\", want \"%s\".", i.Value, rfc3339)
	}
	if i.Note != "" {
		t.Errorf("UNIXTime.Note = \"%v\", want \"\"", i.Note)
	}
	if i.Dump != dump {
		t.Errorf("UNIXTime.Dump = \"%v\", want \"%s\".", i.Dump, dump)
	}
}

func TestExpire(t *testing.T) {
	var d = []byte{0x00, 0x09, 0x3a, 0x80} //604800sec
	utint := int64(0x365e726e)
	dump := "00 09 3a 80"
	rfc3339 := "1998-12-04T09:35:42Z"
	i := NewExpire("name1", d, utint, true).Get()
	if i.Name != "name1" {
		t.Errorf("Expire.Name = \"%v\", want \"name1\".", i.Name)
	}
	if i.Value != "7 days after" {
		t.Errorf("Expire.Value = \"%v\", want \"7 days after\".", i.Value)
	}
	if i.Note != rfc3339 {
		t.Errorf("Expire.Note = \"%v\", want \"%s\"", i.Note, rfc3339)
	}
	if i.Dump != dump {
		t.Errorf("Expire.Dump = \"%v\", want \"%s\".", i.Dump, dump)
	}
}

func TestSigExpire(t *testing.T) {
	var d = []byte{0x00, 0x09, 0x3a, 0x80} //604800sec
	utint := int64(0x365e726e)
	dump := "00 09 3a 80"
	rfc3339 := "1998-12-04T09:35:42Z"
	i := SigExpire(d, utint, true).Get()
	if i.Name != "Signature Expiration Time" {
		t.Errorf("Expire.Name = \"%v\", want \"Signature Expiration Time\".", i.Name)
	}
	if i.Value != "7 days after" {
		t.Errorf("Expire.Value = \"%v\", want \"7 days after\".", i.Value)
	}
	if i.Note != rfc3339 {
		t.Errorf("Expire.Note = \"%v\", want \"%s\"", i.Note, rfc3339)
	}
	if i.Dump != dump {
		t.Errorf("Expire.Dump = \"%v\", want \"%s\".", i.Dump, dump)
	}
}

func TestKeyExpire(t *testing.T) {
	var d = []byte{0x00, 0x09, 0x3a, 0x80} //604800sec
	utint := int64(0x365e726e)
	dump := "00 09 3a 80"
	rfc3339 := "1998-12-04T09:35:42Z"
	i := KeyExpire(d, utint, true).Get()
	if i.Name != "Key Expiration Time" {
		t.Errorf("Expire.Name = \"%v\", want \"Key Expiration Time\".", i.Name)
	}
	if i.Value != "7 days after" {
		t.Errorf("Expire.Value = \"%v\", want \"7 days after\".", i.Value)
	}
	if i.Note != rfc3339 {
		t.Errorf("Expire.Note = \"%v\", want \"%s\"", i.Note, rfc3339)
	}
	if i.Dump != dump {
		t.Errorf("Expire.Dump = \"%v\", want \"%s\".", i.Dump, dump)
	}
}

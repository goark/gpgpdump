package context

import (
	"testing"
)

func TestNewOptions(t *testing.T) {
	o := New()
	res := "armor:false,cert:false,debug:false,gdump:false,int:false,literal:false,marker:false,private:false,utc:false"
	if o.String() != res {
		t.Errorf("Options()  = %v, want %v.", o.String(), res)

	}
}

func TestSetAllOpt(t *testing.T) {
	o := New(
		Set(ARMOR, true),
		Set(CERT, true),
		Set(DEBUG, true),
		Set(GDUMP, true),
		Set(INTEGER, true),
		Set(LITERAL, true),
		Set(MARKER, true),
		Set(PRIVATE, true),
		Set(UTC, true),
	)
	res := "armor:true,cert:true,debug:true,gdump:true,int:true,literal:true,marker:true,private:true,utc:true"
	if o.String() != res {
		t.Errorf("Options()  = %v, want %v.", o.String(), res)
	}
}

func TestArmorOpt(t *testing.T) {
	o := New(SetByString("ARMOR", true))
	res := "armor:true,cert:false,debug:false,gdump:false,int:false,literal:false,marker:false,private:false,utc:false"
	if o.String() != res {
		t.Errorf("Options()  = %v, want %v.", o.String(), res)
	}
}

func TestCertOpt(t *testing.T) {
	o := New(SetByString("CERT", true))
	res := "armor:false,cert:true,debug:false,gdump:false,int:false,literal:false,marker:false,private:false,utc:false"
	if o.String() != res {
		t.Errorf("Options()  = %v, want %v.", o.String(), res)
	}
}

func TestDebugOpt(t *testing.T) {
	o := New(SetByString("DEBUG", true))
	res := "armor:false,cert:true,debug:true,gdump:true,int:true,literal:true,marker:true,private:true,utc:false"
	if o.String() != res {
		t.Errorf("Options()  = %v, want %v.", o.String(), res)
	}
}

func TestGDumpOpt(t *testing.T) {
	o := New(SetByString("GDUMP", true))
	res := "armor:false,cert:false,debug:false,gdump:true,int:false,literal:false,marker:false,private:false,utc:false"
	if o.String() != res {
		t.Errorf("Options()  = %v, want %v.", o.String(), res)
	}
}

func TestIntegerOpt(t *testing.T) {
	o := New(SetByString("INT", true))
	res := "armor:false,cert:false,debug:false,gdump:false,int:true,literal:false,marker:false,private:false,utc:false"
	if o.String() != res {
		t.Errorf("Options()  = %v, want %v.", o.String(), res)
	}
}

func TestLiteralOpt(t *testing.T) {
	o := New(SetByString("Literal", true))
	res := "armor:false,cert:false,debug:false,gdump:false,int:false,literal:true,marker:false,private:false,utc:false"
	if o.String() != res {
		t.Errorf("Options()  = %v, want %v.", o.String(), res)
	}
}

func TestMarkerOpt(t *testing.T) {
	o := New(SetByString("Marker", true))
	res := "armor:false,cert:false,debug:false,gdump:false,int:false,literal:false,marker:true,private:false,utc:false"
	if o.String() != res {
		t.Errorf("Options()  = %v, want %v.", o.String(), res)
	}
}

func TestPrivateOpt(t *testing.T) {
	o := New(SetByString("Private", true))
	res := "armor:false,cert:false,debug:false,gdump:false,int:false,literal:false,marker:false,private:true,utc:false"
	if o.String() != res {
		t.Errorf("Options()  = %v, want %v.", o.String(), res)
	}
}

func TestUTCOpt(t *testing.T) {
	o := New(SetByString("UTC", true))
	res := "armor:false,cert:false,debug:false,gdump:false,int:false,literal:false,marker:false,private:false,utc:true"
	if o.String() != res {
		t.Errorf("Options()  = %v, want %v.", o.String(), res)
	}
}

/* Copyright 2017-2020 Spiegel
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

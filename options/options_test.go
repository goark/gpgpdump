package options

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	//start test
	code := m.Run()

	//termination
	os.Exit(code)
}

func TestNewOptions(t *testing.T) {
	o := New()
	res := "armor:false,debug:false,gdump:false,int:false,literal:false,marker:false,private:false,utc:false"
	if o.String() != res {
		t.Errorf("Options()  = %v, want %v.", o.String(), res)

	}
}

func TestSetAllOpt(t *testing.T) {
	o := New(
		Set(ArmorOpt, true),
		Set(DebugOpt, true), //not use
		Set(GDumpOpt, true), //not use
		Set(IntegerOpt, true),
		Set(LiteralOpt, true),
		Set(MarkerOpt, true),
		Set(PrivateOpt, true),
		Set(UTCOpt, true),
	)
	res := "armor:true,debug:true,gdump:true,int:true,literal:true,marker:true,private:true,utc:true"
	if o.String() != res {
		t.Errorf("Options()  = %v, want %v.", o.String(), res)
	}
}

func TestArmorOpt(t *testing.T) {
	o := New(Set(ArmorOpt, true))
	res := "armor:true,debug:false,gdump:false,int:false,literal:false,marker:false,private:false,utc:false"
	if o.String() != res {
		t.Errorf("Options()  = %v, want %v.", o.String(), res)
	}
}

func TestDebugOpt(t *testing.T) {
	o := New(Set(DebugOpt, true))
	res := "armor:false,debug:true,gdump:false,int:false,literal:false,marker:false,private:false,utc:false"
	if o.String() != res {
		t.Errorf("Options()  = %v, want %v.", o.String(), res)
	}
}

func TestGDumpOpt(t *testing.T) {
	o := New(Set(GDumpOpt, true))
	res := "armor:false,debug:false,gdump:true,int:false,literal:false,marker:false,private:false,utc:false"
	if o.String() != res {
		t.Errorf("Options()  = %v, want %v.", o.String(), res)
	}
}

func TestIntegerOpt(t *testing.T) {
	o := New(Set(IntegerOpt, true))
	res := "armor:false,debug:false,gdump:false,int:true,literal:false,marker:false,private:false,utc:false"
	if o.String() != res {
		t.Errorf("Options()  = %v, want %v.", o.String(), res)
	}
}

func TestLiteralOpt(t *testing.T) {
	o := New(Set(LiteralOpt, true))
	res := "armor:false,debug:false,gdump:false,int:false,literal:true,marker:false,private:false,utc:false"
	if o.String() != res {
		t.Errorf("Options()  = %v, want %v.", o.String(), res)
	}
}

func TestMarkerOpt(t *testing.T) {
	o := New(Set(MarkerOpt, true))
	res := "armor:false,debug:false,gdump:false,int:false,literal:false,marker:true,private:false,utc:false"
	if o.String() != res {
		t.Errorf("Options()  = %v, want %v.", o.String(), res)
	}
}

func TestPrivateOpt(t *testing.T) {
	o := New(Set(PrivateOpt, true))
	res := "armor:false,debug:false,gdump:false,int:false,literal:false,marker:false,private:true,utc:false"
	if o.String() != res {
		t.Errorf("Options()  = %v, want %v.", o.String(), res)
	}
}

func TestUTCOpt(t *testing.T) {
	o := New(Set(UTCOpt, true))
	res := "armor:false,debug:false,gdump:false,int:false,literal:false,marker:false,private:false,utc:true"
	if o.String() != res {
		t.Errorf("Options()  = %v, want %v.", o.String(), res)
	}
}

func TestFakeOpt(t *testing.T) {
	o := New(Set("json", true))
	res := "armor:false,debug:false,gdump:false,int:false,literal:false,marker:false,private:false,utc:false"
	if o.String() != res {
		t.Errorf("Options()  = %v, want %v.", o.String(), res)
	}
}

/* Copyright 2017 Spiegel
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

package values

import (
	"fmt"
	"testing"
)

var testPubIDNames = []string{
	"Unknown (pub 0)",
	"RSA (Encrypt or Sign) (pub 1)",
	"RSA Encrypt-Only (pub 2)",
	"RSA Sign-Only (pub 3)",
	"Unknown (pub 4)",
	"Unknown (pub 5)",
	"Unknown (pub 6)",
	"Unknown (pub 7)",
	"Unknown (pub 8)",
	"Unknown (pub 9)",
	"Unknown (pub 10)",
	"Unknown (pub 11)",
	"Unknown (pub 12)",
	"Unknown (pub 13)",
	"Unknown (pub 14)",
	"Unknown (pub 15)",
	"Elgamal (Encrypt-Only) (pub 16)",
	"DSA (Digital Signature Algorithm) (pub 17)",
	"ECDH public key algorithm (pub 18)",
	"ECDSA public key algorithm (pub 19)",
	"Reserved (formerly Elgamal Encrypt or Sign) (pub 20)",
	"Reserved for Diffie-Hellman (pub 21)",
	"EdDSA (pub 22)",
	"Reserved (AEDH) (pub 23)",
	"Reserved (AEDSA) (pub 24)",
	"Unknown (pub 25)",
}

func TestPubID(t *testing.T) {
	for tag := 0; tag <= 23; tag++ {
		i := PubID(tag).ToItem(false)
		if i.Name != "Public-key Algorithm" {
			t.Errorf("PubID.Name = \"%s\", want \"Public-key Algorithm\".", i.Name)
		}
		if i.Value != testPubIDNames[tag] {
			t.Errorf("PubID.Value = \"%s\", want \"%s\".", i.Value, testPubIDNames[tag])
		}
		if i.Note != "" {
			t.Errorf("PubID.Note = \"%s\", want \"\"", i.Note)
		}
		if i.Dump != "" {
			t.Errorf("PubID.Dump = \"%s\", want \"\".", i.Dump)
		}
	}
	for tag := 100; tag <= 110; tag++ {
		i := PubID(tag).ToItem(false)
		value := fmt.Sprintf("Private/Experimental algorithm (pub %d)", tag)
		if i.Value != value {
			t.Errorf("PubID.Value = \"%s\", want \"%s\".", i.Value, value)
		}
	}
}

func TestPubIDRSA(t *testing.T) {
	for tag := 0; tag <= 23; tag++ {
		pub := PubID(tag)
		switch tag {
		case 1, 2, 3:
			if !pub.IsRSA() {
				t.Errorf("PubID.IsRSA(%d) = %v, want true.", tag, pub.IsRSA())
			}
		default:
			if pub.IsRSA() {
				t.Errorf("PubID.IsRSA(%d) = %v, want false.", tag, pub.IsRSA())
			}
		}
	}
}

func TestPubIDDSA(t *testing.T) {
	for tag := 0; tag <= 23; tag++ {
		pub := PubID(tag)
		switch tag {
		case 17:
			if !pub.IsDSA() {
				t.Errorf("PubID.IsDSA(%d) = %v, want true.", tag, pub.IsDSA())
			}
		default:
			if pub.IsDSA() {
				t.Errorf("PubID.IsDSA(%d) = %v, want false.", tag, pub.IsDSA())
			}
		}
	}
}

func TestPubIDElgamal(t *testing.T) {
	for tag := 0; tag <= 23; tag++ {
		pub := PubID(tag)
		switch tag {
		case 16, 20:
			if !pub.IsElgamal() {
				t.Errorf("PubID.IsElgamal(%d) = %v, want true.", tag, pub.IsElgamal())
			}
		default:
			if pub.IsElgamal() {
				t.Errorf("PubID.IsElgamal(%d) = %v, want false.", tag, pub.IsElgamal())
			}
		}
	}
}

func TestPubIDECDH(t *testing.T) {
	for tag := 0; tag <= 23; tag++ {
		pub := PubID(tag)
		switch tag {
		case 18:
			if !pub.IsECDH() {
				t.Errorf("PubID.IsECDH(%d) = %v, want true.", tag, pub.IsECDH())
			}
		default:
			if pub.IsECDH() {
				t.Errorf("PubID.IsECDH(%d) = %v, want false.", tag, pub.IsECDH())
			}
		}
	}
}

func TestPubIDECDSA(t *testing.T) {
	for tag := 0; tag <= 23; tag++ {
		pub := PubID(tag)
		switch tag {
		case 19:
			if !pub.IsECDSA() {
				t.Errorf("PubID.IsECDSA(%d) = %v, want true.", tag, pub.IsECDSA())
			}
		default:
			if pub.IsECDSA() {
				t.Errorf("PubID.IsECDSA(%d) = %v, want false.", tag, pub.IsECDSA())
			}
		}
	}
}

func TestPubIDEdDSA(t *testing.T) {
	for tag := 0; tag <= 23; tag++ {
		pub := PubID(tag)
		switch tag {
		case 22:
			if !pub.IsEdDSA() {
				t.Errorf("PubID.IsEdDSA(%d) = %v, want true.", tag, pub.IsEdDSA())
			}
		default:
			if pub.IsEdDSA() {
				t.Errorf("PubID.IsEdDSA(%d) = %v, want false.", tag, pub.IsEdDSA())
			}
		}
	}
}

/* Copyright 2016-2021 Spiegel
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

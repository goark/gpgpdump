package context

//SymAlgMode as Sym. algorithm mode
type SymAlgMode int

const (
	//ModeNotSpecified as Not Specified
	ModeNotSpecified SymAlgMode = iota
	//ModeSymEnc as Sym. Encryption Mode
	ModeSymEnc
	//ModePubEnc as Pubkey Encryption Mode
	ModePubEnc
)

func (mode SymAlgMode) String() string {
	switch mode {
	case ModeNotSpecified:
		return "Mode not Specified"
	case ModeSymEnc:
		return "Sym. Encryption Mode"
	case ModePubEnc:
		return "Pubkey Encryption Mode"
	default:
		return "Unknown Mode"
	}
}

//AlgMode returns SymAlgMode
func (mode SymAlgMode) AlgMode() SymAlgMode {
	return mode
}

//IsSymEnc is true when mode is ModeSymEnc
func (mode SymAlgMode) IsSymEnc() bool {
	return mode == ModeSymEnc
}

//IsPubEnc is true when mode is ModePubEnc
func (mode SymAlgMode) IsPubEnc() bool {
	return mode == ModePubEnc
}

//ResetAlg resets SymAlgMode
func (mode *SymAlgMode) ResetAlg() {
	*mode = ModeNotSpecified
}

//SetAlgSymEnc sets SymAlgMode to SymAlgModeSymEnc
func (mode *SymAlgMode) SetAlgSymEnc() {
	*mode = ModeSymEnc
}

//SetAlgPubEnc sets SymAlgMode to SymAlgModePubEnc
func (mode *SymAlgMode) SetAlgPubEnc() {
	*mode = ModePubEnc
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

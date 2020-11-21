package github

import "time"

type OpenPGPKey struct {
	ID                int64         `json:"id"`
	PrimaryKeyID      *int64        `json:"primary_key_id"`
	KeyID             string        `json:"key_id"`
	RawKey            *string       `json:"raw_key"`
	PublicKey         string        `json:"public_key"`
	EMails            []*EMailInfo  `json:"emails"`
	SubKeys           []*OpenPGPKey `json:"subkeys"`
	CanSign           bool          `json:"can_sign"`
	CanEncryptCmms    bool          `json:"can_encrypt_comms"`
	CanEncryptStorage bool          `json:"can_encrypt_storage"`
	CanCertify        bool          `json:"can_certify"`
	CreatedAt         *time.Time    `json:"created_at"`
	ExpiresAt         *time.Time    `json:"expires_at"`
}

type EMailInfo struct {
	EMail    string `json:"email"`
	Verified bool   `json:"verified"`
}

/* Copyright 2020 Spiegel
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

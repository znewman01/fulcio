//go:build cgo
// +build cgo

// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package sshca

import (
	"os"

	"github.com/sigstore/fulcio/pkg/ca"
	"golang.org/x/crypto/ssh"
)

type Params struct {
	KeyPath string
	CAPath  string
}

func NewSSHCA(keyPath, caPath string) (ca.CertificateAuthority, error) {
	certBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	cert, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		return nil, err
	}

	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	key, err := ssh.ParseRawPrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}

	return &SSHCA{
		RootCA:  cert.(*ssh.Certificate),
		PrivKey: signer,
	}, nil
}

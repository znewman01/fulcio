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
	"context"
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"strings"
	"time"

	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/challenges"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"golang.org/x/crypto/ssh"
)

type SSHCA struct {
	RootCA  *ssh.Certificate
	PrivKey ssh.Signer
}

func MakeSSHCert(subject *challenges.ChallengeResult) (*ssh.Certificate, error) {
	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		return nil, err
	}

	sshPubKey, err := ssh.NewPublicKey(subject.PublicKey)
	if err != nil {
		return nil, err // TODO: better rerror
	}

	skid, err := cryptoutils.SKID(subject.PublicKey)
	if err != nil {
		return nil, err
	}

	cert := &ssh.Certificate{
		Key:             sshPubKey,
		Serial:          serialNumber,
		CertType:        ssh.UserCert,
		KeyId:           base64.StdEncoding.EncodeToString(skid),
		ValidPrincipals: []string{subject.Value}, // TODO: use the rest of the ChallengeResult
		ValidAfter:      uint64(time.Now().Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Minute * 10).Unix()),
		// Permissions: maybe a good place to encode misc ChallengeReuslt information
	}

	return cert, nil
}

func (x *SSHCA) Root(ctx context.Context) ([]byte, error) {
	return x.RootCA.Marshal(), nil
}

func (x *SSHCA) CreateCertificate(_ context.Context, subject *challenges.ChallengeResult) (*ca.CodeSigningCertificate, error) {
	cert, err := MakeSSHCert(subject)
	if err != nil {
		return nil, err
	}

	err = cert.SignCert(rand.Reader, x.PrivKey)
	if err != nil {
		return nil, err
	}

	c := &ca.CodeSigningCertificate{
		Subject:       subject,
		FinalPEM:      string(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))),
		FinalChainPEM: []string{strings.TrimSpace(string(ssh.MarshalAuthorizedKey(x.RootCA)))},
	}

	return c, nil
}

func GenerateSerialNumber() (uint64, error) {
	serial, err := rand.Int(rand.Reader, (&big.Int{}).Exp(big.NewInt(2), big.NewInt(63), nil))
	if err != nil {
		return 0, err
	}
	return uint64(serial.Int64()), nil
}

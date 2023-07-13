// Copyright 2022 The Sigstore Authors.
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

package email

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"

	// "encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/asaskevich/govalidator"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/identity"
	"github.com/sigstore/fulcio/pkg/oauthflow"
	"github.com/sigstore/fulcio/pkg/poa"
)

type principal struct {
	address string
	issuer  string
	rawJWT  string
}

func PrincipalFromIDToken(ctx context.Context, token *oidc.IDToken, rawJWT string) (identity.Principal, error) {
	emailAddress, emailVerified, err := oauthflow.EmailFromIDToken(token)
	if err != nil {
		return nil, err
	}
	if !emailVerified {
		return nil, errors.New("email_verified claim was false")
	}

	if !govalidator.IsEmail(emailAddress) {
		return nil, fmt.Errorf("email address is not valid")
	}

	cfg, ok := config.FromContext(ctx).GetIssuer(token.Issuer)
	if !ok {
		return nil, errors.New("invalid configuration for OIDC ID Token issuer")
	}

	issuer, err := oauthflow.IssuerFromIDToken(token, cfg.IssuerClaim)
	if err != nil {
		return nil, err
	}

	return principal{
		issuer:  issuer,
		address: emailAddress,
		rawJWT:  rawJWT,
	}, nil
}

func (p principal) Name(_ context.Context) string {
	return p.address
}

type jwtHeader struct {
	Alg string // `json`:"alg"`
	Kid string // `json`:"kid"`
}

func (p principal) Embed(ctx context.Context, cert *x509.Certificate) error {
	cert.EmailAddresses = []string{p.address}

	jwt := poa.ParseJWT(p.rawJWT)

	var header jwtHeader
	err := json.Unmarshal(jwt.Header, &header)
	if err != nil {
		return err
	}

	// TODO: use the cached JWKs. There's no easy access so we just re-request here.
	set, err := jwk.Fetch(ctx, "https://oauth2.sigstore.dev/auth/keys")
	if err != nil {
		return err
	}
	var matchingKey jwk.Key
	found := false
	for it := set.Iterate(ctx); it.Next(ctx); {
		pair := it.Pair()
		key := pair.Value.(jwk.Key)

		if key.KeyID() == header.Kid {
			found = true
			matchingKey = key
		}
	}

	ext := certificate.Extensions{
		Issuer:   p.issuer,
		JWTNoSig: string(jwt.SignedPart()),
	}
	if found {
		// Base64urlUInt-encoded
		rsaPubJwk := matchingKey.(jwk.RSAPublicKey)
		e := new(big.Int).SetBytes(rsaPubJwk.E())
		n := new(big.Int).SetBytes(rsaPubJwk.N())
		rsaPub := rsa.PublicKey{n, int(e.Int64())}
		if !jwt.Verify(&rsaPub) {
			return fmt.Errorf("uh oh")
		}

		proof := jwt.GQProve(&rsaPub)
		proofJson, jsonErr := json.Marshal(proof)
		if jsonErr != nil {
			return jsonErr
		}
		ext.GQProof = string(proofJson)
	}
	cert.ExtraExtensions, err = ext.Render()
	if err != nil {
		return err
	}

	return nil
}

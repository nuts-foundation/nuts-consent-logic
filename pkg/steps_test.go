/*
 *  Nuts consent logic holds the logic for consent creation
 *  Copyright (C) 2019 Nuts community
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package pkg

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/lestrrat-go/jwx/jwa"
	cStoreMock "github.com/nuts-foundation/nuts-consent-store/mock"
	cStoreTypes "github.com/nuts-foundation/nuts-consent-store/pkg"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	cryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg/types"
	"github.com/nuts-foundation/nuts-registry/mock"
	"github.com/nuts-foundation/nuts-registry/pkg/db"
	"github.com/stretchr/testify/assert"
)

func TestConsentLogic_getVersionID(t *testing.T) {
	ctrl := gomock.NewController(t)
	cStore := cStoreMock.NewMockConsentStoreClient(ctrl)
	cl := ConsentLogic{NutsConsentStore: cStore}

	t.Run("version for new record equals 1", func(t *testing.T) {
		v, _ := cl.getVersionID(Record{})
		assert.Equal(t, uint(1), v)
	})

	t.Run("version for updated record equals +1", func(t *testing.T) {
		h := "hash"
		cStore.EXPECT().FindConsentRecordByHash(context.TODO(), h, true).Return(cStoreTypes.ConsentRecord{Version: 1}, nil)

		v, _ := cl.getVersionID(Record{PreviousRecordhash: &h})
		assert.Equal(t, uint(2), v)
	})

	t.Run("version for unknown record returns error", func(t *testing.T) {
		h := "hash"
		cStore.EXPECT().FindConsentRecordByHash(context.TODO(), h, true).Return(cStoreTypes.ConsentRecord{}, cStoreTypes.ErrorNotFound)

		_, err := cl.getVersionID(Record{PreviousRecordhash: &h})
		if assert.Error(t, err) {
			assert.True(t, errors.Is(err, cStoreTypes.ErrorNotFound))
		}
	})

	t.Run("version for not-latest record returns error", func(t *testing.T) {
		h := "hash"
		cStore.EXPECT().FindConsentRecordByHash(context.TODO(), h, true).Return(cStoreTypes.ConsentRecord{}, cStoreTypes.ErrorConsentRecordNotLatest)

		_, err := cl.getVersionID(Record{PreviousRecordhash: &h})
		if assert.Error(t, err) {
			assert.True(t, errors.Is(err, cStoreTypes.ErrorConsentRecordNotLatest))
		}
	})
}

func TestCreateFhirConsentResource(t *testing.T) {
	defer resetTestTime()
	tt, _ := time.Parse(time.RFC3339, "2019-01-01T11:00:00Z")

	nutsTime = testTime{
		testTime: tt,
	}

	type args struct {
		request CreateConsentRequest
	}

	validConsent, err := ioutil.ReadFile("../test-data/valid-consent.json")
	if err != nil {
		t.Error(err)
	}

	performerId := IdentifierURI("urn:oid:2.16.840.1.113883.2.4.6.1:00000003")
	url := "https://some.url/reference.pdf"
	contentType := "application/pdf"
	hash := "hash"

	endDate := time.Date(2019, time.July, 1, 11, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		args    args
		want    interface{}
		wantErr bool
	}{
		{
			"it can create a valid consent",
			args{
				CreateConsentRequest{
					Subject:   "urn:oidurn:oid:2.16.840.1.113883.2.4.6.3:999999990",
					Custodian: "urn:oid:2.16.840.1.113883.2.4.6.1:00000000",
					Actor: IdentifierURI(
						"urn:oid:2.16.840.1.113883.2.4.6.1:00000001",
					),
					Records: []Record{{
						Period: Period{
							Start: time.Date(2019, time.January, 1, 11, 0, 0, 0, time.UTC),
							End:   &endDate,
						},
						ConsentProof: &DocumentReference{
							Title:       "title",
							ID:          "id",
							URL:         &url,
							ContentType: &contentType,
							Hash:        &hash,
						},
						DataClass: []IdentifierURI{
							IdentifierURI("urn:oid:1.3.6.1.4.1.54851.1:MEDICAL"),
							IdentifierURI("urn:oid:1.3.6.1.4.1.54851.1:SOCIAL"),
						},
					}},
					Performer: &performerId,
				},
			},
			string(validConsent),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var o1 interface{}
			var o2 interface{}

			_ = json.Unmarshal(validConsent, &o1)
			got, err := ConsentLogic{}.createFhirConsentResource(tt.args.request.Custodian, tt.args.request.Actor, tt.args.request.Subject, *tt.args.request.Performer, tt.args.request.Records[0])
			if err != nil {
				t.Error(err)
			}

			err = json.Unmarshal([]byte(got), &o2)

			if err != nil {
				t.Error(err)
			}

			assert.Equal(t, tt.wantErr, err != nil)
			assert.Equal(t, o1, o2)
		})
	}
}

func TestEncryptFhirConsent(t *testing.T) {
	validConsent, err := ioutil.ReadFile("../test-data/valid-consent.json")
	if err != nil {
		t.Error(err)
	}

	custodianID := "agb:00000001"
	partyID := "agb:00000002"

	cryptoClient := crypto.NewCryptoClient()
	_ = cryptoClient.GenerateKeyPairFor(cryptoTypes.LegalEntity{URI: custodianID})
	publicKey, _ := cryptoClient.PublicKeyInJWK(cryptoTypes.LegalEntity{URI: custodianID})
	jwkMap, _ := crypto.JwkToMap(publicKey)
	jwkMap["kty"] = jwkMap["kty"].(jwa.KeyType).String() // annoying thing from jwk lib

	t.Run("it should encrypt the consent resource", func(tt *testing.T) {
		ctrl := gomock.NewController(tt)
		registryClient := mock.NewMockRegistryClient(ctrl)
		cl := ConsentLogic{
			NutsCrypto:   cryptoClient,
			NutsRegistry: registryClient,
		}
		defer ctrl.Finish()
		registryClient.EXPECT().OrganizationById(gomock.Eq(partyID)).Return(&db.Organization{Keys: []interface{}{jwkMap}}, nil)

		request := CreateConsentRequest{
			Actor:     IdentifierURI(partyID),
			Custodian: IdentifierURI(custodianID),
		}

		encryptedContent, err := cl.encryptFhirConsent(string(validConsent), request)

		if err != nil {
			t.Errorf("EncryptFhirConsent() error = %v", err)
			return
		}
		// decrypt the content for the custodian and compare
		result, err := cryptoClient.DecryptKeyAndCipherTextFor(cryptoTypes.DoubleEncryptedCipherText{
			CipherText:     encryptedContent.CipherText,
			CipherTextKeys: [][]byte{encryptedContent.CipherTextKeys[0]},
			Nonce:          encryptedContent.Nonce,
		}, cryptoTypes.LegalEntity{URI: custodianID})
		if err != nil {
			t.Error("Error while decrypting text:", err)
		}
		if string(result) != string(validConsent) {
			t.Errorf("Decrypting content failed. Got: %v, wanted: %v", result, string(validConsent))
		}
	})
}

func TestGetConsentId(t *testing.T) {
	type args struct {
		request CreateConsentRequest
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"it generates a externalId",
			args{
				request: CreateConsentRequest{Custodian: "agb#00000012", Actor: IdentifierURI("actor"), Subject: IdentifierURI("subject")},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			cClient := crypto.NewCryptoClient()
			_ = cClient.GenerateKeyPairFor(types.LegalEntity{URI: string(tt.args.request.Custodian)})

			got, err := ConsentLogic{
				NutsCrypto: cClient,
			}.getConsentID(tt.args.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetConsentId() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(got) != 64 {
				t.Errorf("Expected length of externalId to be 64 got %v instead", len(got))
			}
		})
	}
}

func Test_validateFhirConsentResource(t *testing.T) {
	validConsent, err := ioutil.ReadFile("../test-data/valid-consent.json")
	if err != nil {
		t.Error(err)
	}

	type args struct {
		consentResource string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			"it should validate a schema",
			args{string(validConsent)},
			true,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConsentLogic{}.validateFhirConsentResource(tt.args.consentResource)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFhirConsentResource() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ValidateFhirConsentResource() = %v, want %v", got, tt.want)
			}
		})
	}
}

type testTime struct {
	testTime time.Time
}

func (tt testTime) Now() time.Time {
	return tt.testTime
}

func resetTestTime() {
	nutsTime = realNutsTime{}
}

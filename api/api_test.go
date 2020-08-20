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

package api

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"github.com/nuts-foundation/nuts-consent-logic/test"
	"net/http"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-consent-logic/pkg"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/cert"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	cryptomock "github.com/nuts-foundation/nuts-crypto/test/mock"
	mock2 "github.com/nuts-foundation/nuts-event-octopus/mock"
	pkg2 "github.com/nuts-foundation/nuts-event-octopus/pkg"
	registrymock "github.com/nuts-foundation/nuts-registry/mock"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	"github.com/nuts-foundation/nuts-registry/pkg/db"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-go-core/mock"
)

var actorID = IdentifierURI(test.AGBPartyID("00000001").String())
var performerID = IdentifierURI(test.AGBPartyID("00000007").String())
var custodianID = IdentifierURI(test.AGBPartyID("00000007").String())
var subjectID = IdentifierURI(test.BSNPartyID("99999990").String())

type EventPublisherMock struct{}

func (EventPublisherMock) Publish(subject string, event pkg2.Event) error {
	return nil
}

func jsonRequest() CreateConsentRequest {
	// optional params:
	endDate := time.Date(2019, time.July, 1, 11, 0, 0, 0, time.UTC)

	// complete request
	return CreateConsentRequest{
		Records: []ConsentRecord{
			{
				Period:       Period{Start: time.Now(), End: &endDate},
				ConsentProof: DocumentReference{Title: "proof", ID: "1"},
				DataClass: []DataClassification{
					"urn:oid:1.3.6.1.4.1.54851.1:MEDICAL",
				},
			},
			{
				Period:       Period{Start: time.Now(), End: &endDate},
				ConsentProof: DocumentReference{Title: "other.proof", ID: "2"},
				DataClass: []DataClassification{
					"urn:oid:1.3.6.1.4.1.54851.1:SOCIAL",
				},
			},
		},
		Actor:     actorID,
		Custodian: custodianID,
		Subject:   subjectID,
		Performer: &performerID,
	}

}

func TestApiResource_NutsConsentLogicCreateConsent(t *testing.T) {

	t.Run("It starts a consent flow", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		registryMock := registrymock.NewMockRegistryClient(ctrl)
		cryptoMock := cryptomock.NewMockClient(ctrl)
		octoMock := mock2.NewMockEventOctopusClient(ctrl)
		sk, _ := rsa.GenerateKey(rand.Reader, 1024)
		publicKey, _ := jwk.New(sk.Public())
		jwkMap, _ := cert.JwkToMap(publicKey)
		jwkMap["kty"] = jwkMap["kty"].(jwa.KeyType).String() // annoying thing from jwk lib
		registryMock.EXPECT().OrganizationById(actorID.PartyID()).Return(&db.Organization{Keys: []interface{}{jwkMap}}, nil).Times(2)
		cryptoMock.EXPECT().GetPublicKeyAsJWK(gomock.Any()).Return(publicKey, nil).AnyTimes()
		cryptoMock.EXPECT().PrivateKeyExists(gomock.Any()).Return(true).AnyTimes()
		cryptoMock.EXPECT().CalculateExternalId(gomock.Any(), gomock.Any(), gomock.Any()).Return([]byte("123external_id"), nil)
		cryptoMock.EXPECT().EncryptKeyAndPlainText(gomock.Any(), gomock.Any()).Return(types.DoubleEncryptedCipherText{}, nil).Times(2)
		octoMock.EXPECT().EventPublisher(gomock.Any()).Return(&EventPublisherMock{}, nil)

		apiWrapper := wrapper(registryMock, cryptoMock, octoMock)
		defer ctrl.Finish()
		echoServer := mock.NewMockContext(ctrl)

		jsonData, _ := json.Marshal(jsonRequest())

		echoServer.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})

		// setup response expectation

		echoServer.EXPECT().JSON(http.StatusAccepted, JobCreatedResponseMatcher{})

		assert.NoError(t, apiWrapper.CreateOrUpdateConsent(echoServer))
	})
	t.Run("It handles an empty request body", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		apiWrapper := Wrapper{}
		echoServer := mock.NewMockContext(ctrl)
		echoServer.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {})

		err := apiWrapper.CreateOrUpdateConsent(echoServer)
		if assert.Error(t, err) {
			assert.Equal(t, "the consent requires a custodian", err.(*echo.HTTPError).Message)
		}
	})

	t.Run("It handles a missing subject", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		apiWrapper := Wrapper{}
		echoServer := mock.NewMockContext(ctrl)

		jsonRequest := jsonRequest()
		jsonRequest.Subject = ""
		jsonData, _ := json.Marshal(jsonRequest)

		echoServer.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})

		err := apiWrapper.CreateOrUpdateConsent(echoServer)
		if assert.Error(t, err) {
			assert.Equal(t, "the consent requires a subject", err.(*echo.HTTPError).Message)
		}
	})
	t.Run("It handles a missing actor", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		apiWrapper := Wrapper{}
		echoServer := mock.NewMockContext(ctrl)

		jsonRequest := jsonRequest()
		jsonRequest.Actor = ""
		jsonData, _ := json.Marshal(jsonRequest)

		echoServer.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})

		err := apiWrapper.CreateOrUpdateConsent(echoServer)
		if assert.Error(t, err) {
			assert.Equal(t, "the consent requires an actor", err.(*echo.HTTPError).Message)
		}
	})

	t.Run("It handles empty record array", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		apiWrapper := Wrapper{}
		echoServer := mock.NewMockContext(ctrl)

		jsonRequest := jsonRequest()
		jsonRequest.Records = []ConsentRecord{}
		jsonData, _ := json.Marshal(jsonRequest)

		echoServer.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})

		err := apiWrapper.CreateOrUpdateConsent(echoServer)
		if assert.Error(t, err) {
			assert.Equal(t, "the consent requires at least one record", err.(*echo.HTTPError).Message)
		}
	})

	t.Run("A record must have a period.start", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		apiWrapper := Wrapper{}
		echoServer := mock.NewMockContext(ctrl)

		jsonRequest := jsonRequest()
		jsonRequest.Records[0].Period.Start = time.Time{}
		jsonData, _ := json.Marshal(jsonRequest)

		echoServer.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})

		err := apiWrapper.CreateOrUpdateConsent(echoServer)
		if assert.Error(t, err) {
			assert.Equal(t, "the consent record requires a period.start", err.(*echo.HTTPError).Message)
		}
	})

	t.Run("A record must have a valid proof", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		apiWrapper := Wrapper{}
		echoServer := mock.NewMockContext(ctrl)

		jsonRequest := jsonRequest()
		jsonRequest.Records[0].ConsentProof = DocumentReference{}
		jsonData, _ := json.Marshal(jsonRequest)

		echoServer.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})

		err := apiWrapper.CreateOrUpdateConsent(echoServer)
		if assert.Error(t, err) {
			assert.Equal(t, "the consent record requires a valid proof", err.(*echo.HTTPError).Message)
		}
	})

	t.Run("A record must have a valid data class", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		apiWrapper := Wrapper{}
		echoServer := mock.NewMockContext(ctrl)

		jsonRequest := jsonRequest()
		jsonRequest.Records[0].DataClass = nil
		jsonData, _ := json.Marshal(jsonRequest)

		echoServer.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})

		err := apiWrapper.CreateOrUpdateConsent(echoServer)
		if assert.Error(t, err) {
			assert.Equal(t, "the consent record requires at least one data class", err.(*echo.HTTPError).Message)
		}
	})

	t.Run("A data class can not be empty", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		apiWrapper := Wrapper{}
		echoServer := mock.NewMockContext(ctrl)

		jsonRequest := jsonRequest()
		jsonRequest.Records[0].DataClass = []DataClassification{""}
		jsonData, _ := json.Marshal(jsonRequest)

		echoServer.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})

		err := apiWrapper.CreateOrUpdateConsent(echoServer)
		if assert.Error(t, err) {
			assert.Equal(t, "a data class can not be empty", err.(*echo.HTTPError).Message)
		}
	})

	t.Run("A data class can not have the incorrect format", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		apiWrapper := Wrapper{}
		echoServer := mock.NewMockContext(ctrl)

		jsonRequest := jsonRequest()
		jsonRequest.Records[0].DataClass = []DataClassification{"some classification"}
		jsonData, _ := json.Marshal(jsonRequest)

		echoServer.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})

		err := apiWrapper.CreateOrUpdateConsent(echoServer)
		if assert.Error(t, err) {
			assert.Equal(t, "a data class must start with urn:oid:1.3.6.1.4.1.54851.1:", err.(*echo.HTTPError).Message)
		}
	})

}

func Test_apiRequest2Internal(t *testing.T) {
	t.Run("ok", func(t *testing.T) {

		previousId := "-1"
		start := time.Time{}
		end := time.Time{}.AddDate(1, 0, 0)

		url := "url"
		contentType := "text/plain"
		hash := "hash"

		apiRequest := CreateConsentRequest{
			Actor:     actorID,
			Custodian: custodianID,
			Subject:   subjectID,
			Performer: &performerID,
			Records: []ConsentRecord{{
				ConsentProof: DocumentReference{
					ID:          "3",
					Title:       "some.consent.doc",
					URL:         &url,
					ContentType: &contentType,
					Hash:        &hash,
				},
				DataClass: []DataClassification{
					"urn:oid:1.3.6.1.4.1.54851.1:MEDICAL",
				},
				PreviousRecordHash: &previousId,
				Period: Period{
					End:   &end,
					Start: start,
				},
			}},
		}
		internal := apiRequest2Internal(apiRequest)

		assert.Equal(t, actorID.PartyID(), internal.Actor)
		assert.Equal(t, custodianID.PartyID(), internal.Custodian)
		assert.Equal(t, subjectID.PartyID(), internal.Subject)
		assert.Equal(t, performerID.PartyID(), internal.Performer)
		assert.Len(t, internal.Records, 1)

		internalRecord := internal.Records[0]
		apiRecord := apiRequest.Records[0]

		assert.Equal(t, *internalRecord.PreviousRecordhash, *apiRecord.PreviousRecordHash)
		assert.Equal(t, internalRecord.ConsentProof.Title, apiRecord.ConsentProof.Title)
		assert.Equal(t, internalRecord.ConsentProof.ID, apiRecord.ConsentProof.ID)
		assert.Equal(t, *internalRecord.ConsentProof.ContentType, *apiRecord.ConsentProof.ContentType)
		assert.Equal(t, *internalRecord.ConsentProof.URL, *apiRecord.ConsentProof.URL)
		assert.Equal(t, *internalRecord.ConsentProof.Hash, *apiRecord.ConsentProof.Hash)
		assert.Equal(t, start, internalRecord.Period.Start)
		assert.Equal(t, end, *internalRecord.Period.End)

		assert.Len(t, internalRecord.DataClass, 1)
		assert.Equal(t, string(internalRecord.DataClass[0]), string(apiRecord.DataClass[0]))
	})
	t.Run("ok - performer empty", func(t *testing.T) {
		apiRequest := CreateConsentRequest{
			Actor:     actorID,
			Custodian: custodianID,
			Subject:   subjectID,
			Performer: nil,
		}
		internal := apiRequest2Internal(apiRequest)
		assert.True(t, internal.Performer.IsZero())
	})
}

// A matcher to check for successful jobCreateResponse
type JobCreatedResponseMatcher struct{}

// Matches a valid UUID and
func (JobCreatedResponseMatcher) Matches(x interface{}) bool {
	jobID := x.(JobCreatedResponse).JobId
	if jobID == nil {
		return false
	}
	uuid, err := uuid.FromString(*jobID)
	correctVersion := uuid.Version() == 4
	return err == nil && correctVersion && x.(JobCreatedResponse).ResultCode == "OK"
}
func (JobCreatedResponseMatcher) String() string {
	return "a successful created job"
}

func wrapper(registryClient registry.RegistryClient, cryptoClient crypto.Client, octopusClient pkg2.EventOctopusClient) *Wrapper {

	publisher, err := octopusClient.EventPublisher("consent-logic")
	if err != nil {
		logrus.WithError(err).Panic("Could not subscribe to event publisher")
	}

	return &Wrapper{
		Cl: &pkg.ConsentLogic{
			NutsRegistry:     registryClient,
			NutsCrypto:       cryptoClient,
			NutsEventOctopus: octopusClient,
			EventPublisher:   publisher,
		},
	}
}

/*
 * This file is part of nuts-consent-logic.
 *
 * nuts-consent-logic is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nuts-consent-logic is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with nuts-consent-logic.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package api

import (
	"encoding/json"
	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-consent-logic/pkg"
	cryptomock "github.com/nuts-foundation/nuts-crypto/mock"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	mock2 "github.com/nuts-foundation/nuts-event-octopus/mock"
	pkg2 "github.com/nuts-foundation/nuts-event-octopus/pkg"
	registrymock "github.com/nuts-foundation/nuts-registry/mock"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	"github.com/nuts-foundation/nuts-registry/pkg/db"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-go-core/mock"
)

type EventPublisherMock struct{}

func (EventPublisherMock) Publish(subject string, event pkg2.Event) error {
	return nil
}

func TestApiResource_NutsConsentLogicCreateConsent(t *testing.T) {
	t.Run("It starts a consent flow", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		registryMock := registrymock.NewMockRegistryClient(ctrl)
		cryptoMock := cryptomock.NewMockClient(ctrl)
		octoMock := mock2.NewMockEventOctopusClient(ctrl)

		publicKey := "123"
		endDate := time.Date(2019, time.July, 1, 11, 0, 0, 0, time.UTC)

		registryMock.EXPECT().OrganizationById("agb:00000001").Return(&db.Organization{PublicKey: &publicKey}, nil).Times(2)
		cryptoMock.EXPECT().PublicKey(gomock.Any()).Return(publicKey, nil).AnyTimes()
		cryptoMock.EXPECT().ExternalIdFor(gomock.Any(), gomock.Any(), gomock.Any()).Return([]byte("123external_id"), nil)
		cryptoMock.EXPECT().EncryptKeyAndPlainTextWith(gomock.Any(), gomock.Any()).Return(types.DoubleEncryptedCipherText{}, nil).Times(2)
		octoMock.EXPECT().EventPublisher(gomock.Any()).Return(&EventPublisherMock{}, nil)

		apiWrapper := wrapper(registryMock, cryptoMock, octoMock)
		defer ctrl.Finish()
		echoServer := mock.NewMockContext(ctrl)

		performer := IdentifierURI("agb:00000007")

		// provide the request
		jsonRequest := &CreateConsentRequest{
			Records: []ConsentRecord{
				{
					Period:       Period{Start: time.Now(), End: &endDate},
					ConsentProof: struct{ EmbeddedData }{EmbeddedData: EmbeddedData{Data: "proof", ContentType: "text/plain"}},
				},
				{
					Period:       Period{Start: time.Now(), End: &endDate},
					ConsentProof: struct{ EmbeddedData }{EmbeddedData: EmbeddedData{Data: "other proof", ContentType: "text/plain"}},
				},
			},
			Actor:     ActorURI("agb:00000001"),
			Custodian: CustodianURI("agb:00000007"),
			Subject:   SubjectURI("bsn:99999990"),
			Performer: &performer,
		}

		jsonData, _ := json.Marshal(*jsonRequest)

		echoServer.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})

		// setup response expectation

		echoServer.EXPECT().JSON(http.StatusAccepted, JobCreatedResponseMatcher{})
		err := apiWrapper.CreateOrUpdateConsent(echoServer)

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
	})
	t.Run("It handles an empty request body", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		apiWrapper := Wrapper{}
		echoServer := mock.NewMockContext(ctrl)
		echoServer.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {})

		err := apiWrapper.CreateOrUpdateConsent(echoServer)
		if assert.Error(t, err) {
			assert.Equal(t, err.(*echo.HTTPError).Message, "the consent requires at least one record")
		}
	})
}

func Test_apiRequest2Internal(t *testing.T) {
	performer := IdentifierURI("performer")
	previousId := "-1"
	start := time.Time{}
	end := time.Time{}.AddDate(1, 0, 0)

	apiRequest := CreateConsentRequest{
		Actor:     "actor",
		Custodian: "custodian",
		Subject:   "subject",
		Performer: &performer,
		Records: []ConsentRecord{{
			ConsentProof: struct{ EmbeddedData }{EmbeddedData: EmbeddedData{
				ContentType: "text/plain",
				Data:        "base64encodedProof",
			}},
			PreviousRecordID: &previousId,
			Period: Period{
				End:   &end,
				Start: start,
			},
		}},
	}
	internal := apiRequest2Internal(apiRequest)
	if internal.Actor != "actor" || internal.Custodian != "custodian" || internal.Subject != "subject" || *internal.Performer != "performer" || len(internal.Records) != 1 {
		t.Errorf("wrong conversion of apiRequest to internal format. apiRequest: %+v, internalFormat: %+v", apiRequest, internal)
	}

	internalRecord := internal.Records[0]
	apiRecord := apiRequest.Records[0]
	if *internalRecord.PreviousRecordID != *apiRecord.PreviousRecordID ||
		internalRecord.ConsentProof.Data != apiRecord.ConsentProof.Data ||
		internalRecord.ConsentProof.ContentType != "text/plain" ||
		internalRecord.Period.Start != start || internalRecord.Period.End != &end {
		t.Errorf("wrong conversion of internalRecord. apiRecord: %+v, internalRecord: %+v", apiRecord, internalRecord)
	}
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

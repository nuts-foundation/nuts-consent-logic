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
	"github.com/nuts-foundation/nuts-consent-logic/pkg"
	cryptomock "github.com/nuts-foundation/nuts-crypto/mock"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	mock2 "github.com/nuts-foundation/nuts-event-octopus/mock"
	pkg2 "github.com/nuts-foundation/nuts-event-octopus/pkg"
	registrymock "github.com/nuts-foundation/nuts-registry/mock"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	"github.com/nuts-foundation/nuts-registry/pkg/db"
	"github.com/sirupsen/logrus"
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

		registryMock.EXPECT().OrganizationById("agb:00000001").Return(&db.Organization{PublicKey: &publicKey}, nil)
		registryMock.EXPECT().OrganizationById("agb:00000002").Return(&db.Organization{PublicKey: &publicKey}, nil)
		cryptoMock.EXPECT().PublicKey(gomock.Any()).Return(publicKey, nil).AnyTimes()
		cryptoMock.EXPECT().ExternalIdFor(gomock.Any(), gomock.Any()).Return([]byte("123external_id"), nil)
		cryptoMock.EXPECT().EncryptKeyAndPlainTextWith(gomock.Any(), gomock.Any()).Return(types.DoubleEncryptedCipherText{}, nil)
		octoMock.EXPECT().EventPublisher(gomock.Any()).Return(&EventPublisherMock{}, nil)

		apiWrapper := wrapper(registryMock, cryptoMock, octoMock)
		defer ctrl.Finish()
		echoServer := mock.NewMockContext(ctrl)

		performer := IdentifierURI("agb:00000007")

		// provide the request
		jsonRequest := &CreateConsentRequest{
			Actors:    []ActorURI{"agb:00000001", "agb:00000002"},
			Custodian: CustodianURI("agb:00000007"),
			Subject:   SubjectURI("bsn:99999990"),
			Period:    &Period{Start: time.Now(), End: &endDate},
			Performer: &performer,
		}

		jsonData, _ := json.Marshal(*jsonRequest)

		echoServer.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})

		// setup response expectation
		echoServer.EXPECT().JSON(http.StatusAccepted, gomock.Any())

		err := apiWrapper.NutsConsentLogicCreateConsent(echoServer)

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
	})
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

func TestApiResource_NutsConsentLogicValidateConsent(t *testing.T) {
}

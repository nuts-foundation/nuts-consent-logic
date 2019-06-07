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
	cryptoMock "github.com/nuts-foundation/nuts-crypto/mock"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	registryMock "github.com/nuts-foundation/nuts-registry/mock"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	"github.com/nuts-foundation/nuts-registry/pkg/db"
	"net/http"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-go/mock"
)

func TestApiResource_NutsConsentLogicCreateConsent(t *testing.T) {
	t.Run("It start a consent flow", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		registryMock := registryMock.NewMockRegistryClient(ctrl)
		cryptoMock := cryptoMock.NewMockClient(ctrl)

		publicKey := "123"

		registryMock.EXPECT().OrganizationById("agb:00000001").Return(&db.Organization{PublicKey: &publicKey}, nil)
		registryMock.EXPECT().OrganizationById("agb:00000002").Return(&db.Organization{PublicKey: &publicKey}, nil)
		cryptoMock.EXPECT().ExternalIdFor(gomock.Any(), gomock.Any()).Return([]byte("123external_id"), nil)
		cryptoMock.EXPECT().EncryptKeyAndPlainTextWith(gomock.Any(), gomock.Any()).Return(types.DoubleEncryptedCipherText{}, nil)

		apiWrapper := wrapper(registryMock, cryptoMock)
		defer ctrl.Finish()
		echoServer := mock.NewMockContext(ctrl)

		performer := IdentifierURI("agb:00000007")

		// provide the request
		jsonRequest := &CreateConsentRequest{
			Actors:    []ActorURI{"agb:00000001", "agb:00000002"},
			Custodian: CustodianURI("agb:00000007"),
			Subject:   SubjectURI("bsn:99999990"),
			Period:    &Period{Start: time.Now(), End: time.Now()},
			Performer: &performer,
		}

		jsonData, _ := json.Marshal(*jsonRequest)

		echoServer.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			json.Unmarshal(jsonData, f)
		})

		// setup response expectation
		echoServer.EXPECT().JSON(http.StatusAccepted, gomock.Any())

		apiWrapper.NutsConsentLogicCreateConsent(echoServer)
	})
}

func wrapper(registryClient registry.RegistryClient, cryptoClient crypto.Client) *Wrapper {
	return &Wrapper{
		Cl: &pkg.ConsentLogic{
			NutsRegistry: registryClient,
			NutsCrypto:   cryptoClient,
		},
	}
}

func TestApiResource_NutsConsentLogicValidateConsent(t *testing.T) {
}

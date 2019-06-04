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

package steps

import (
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-consent-logic/generated"
	types "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/crypto"
	registryTypes "github.com/nuts-foundation/nuts-registry/pkg"
	registryGenerated "github.com/nuts-foundation/nuts-registry/pkg/generated"
	"github.com/nuts-foundation/nuts-registry/pkg/registry"
	"io/ioutil"
	"testing"
)

func TestEncryptFhirConsent(t *testing.T) {
	validConsent, err := ioutil.ReadFile("../../test-data/valid-consent.json")
	if err != nil {
		t.Error(err)
	}

	custodianId := types.LegalEntity{URI: "agb:00000001"}
	party1Id := types.LegalEntity{URI: "agb:00000002"}
	party2Id := types.LegalEntity{URI: "agb:00000003"}

	cryptoClient := crypto.NewCryptoClient()
	cryptoClient.GenerateKeyPairFor(custodianId)
	publicKey, _ := cryptoClient.PublicKey(custodianId)

	t.Run("it should encrypt the consent resource", func(tt *testing.T) {
		ctrl := gomock.NewController(tt)
		registryClient := registry.NewMockClient(ctrl)
		defer ctrl.Finish()
		registryClient.EXPECT().OrganizationById(gomock.Eq(registryTypes.LegalEntity{URI:party1Id.URI})).Return(&registryGenerated.Organization{PublicKey: &publicKey}, nil)
		registryClient.EXPECT().OrganizationById(gomock.Eq(registryTypes.LegalEntity{URI:party2Id.URI})).Return(&registryGenerated.Organization{PublicKey: &publicKey}, nil)

		request := generated.CreateConsentRequest{
			Actors: []generated.ActorURI{
				generated.ActorURI(party1Id.URI), generated.ActorURI(party2Id.URI),
			},
			Custodian: generated.CustodianURI(custodianId.URI),
		}

		encryptedContent, err := EncryptFhirConsent(registryClient, string(validConsent), request)

		if err != nil {
			t.Errorf("EncryptFhirConsent() error = %v", err)
			return
		}
		// decrypt the content for the custodian and compare
		result, err := cryptoClient.DecryptKeyAndCipherTextFor(types.DoubleEncryptedCipherText{
			encryptedContent.CipherText,
			[][]byte{encryptedContent.CipherTextKeys[0]},
			encryptedContent.Nonce,
		}, custodianId,
		)
		if err != nil {
			t.Error("Error while decrypting text:", err)
		}
		if string(result) != string(validConsent) {
			t.Errorf("Decrypting content failed. Got: %v, wanted: %v", result, string(validConsent))
		}
	})
}

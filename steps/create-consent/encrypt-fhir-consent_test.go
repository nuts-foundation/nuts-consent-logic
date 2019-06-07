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
	"github.com/nuts-foundation/nuts-consent-logic/pkg"
	types "github.com/nuts-foundation/nuts-crypto/pkg"
	types2 "github.com/nuts-foundation/nuts-crypto/pkg/types"
	"github.com/nuts-foundation/nuts-registry/mock"
	"github.com/nuts-foundation/nuts-registry/pkg/db"
	"io/ioutil"
	"testing"
)

func TestEncryptFhirConsent(t *testing.T) {
	validConsent, err := ioutil.ReadFile("../../test-data/valid-consent.json")
	if err != nil {
		t.Error(err)
	}

	custodianId := "agb:00000001"
	party1Id := "agb:00000002"
	party2Id := "agb:00000003"

	cryptoClient := types.NewCryptoClient()
	cryptoClient.GenerateKeyPairFor(types2.LegalEntity{URI: custodianId})
	publicKey, _ := cryptoClient.PublicKey(types2.LegalEntity{URI: custodianId})

	t.Run("it should encrypt the consent resource", func(tt *testing.T) {
		ctrl := gomock.NewController(tt)
		registryClient := mock.NewMockRegistryClient(ctrl)
		defer ctrl.Finish()
		registryClient.EXPECT().OrganizationById(gomock.Eq(party1Id)).Return(&db.Organization{PublicKey: &publicKey}, nil)
		registryClient.EXPECT().OrganizationById(gomock.Eq(party2Id)).Return(&db.Organization{PublicKey: &publicKey}, nil)

		request := pkg.CreateConsentRequest{
			Actors: []pkg.IdentifierURI{
				pkg.IdentifierURI(party1Id), pkg.IdentifierURI(party2Id),
			},
			Custodian: pkg.IdentifierURI(custodianId),
		}

		encryptedContent, err := EncryptFhirConsent(registryClient, cryptoClient, string(validConsent), request)

		if err != nil {
			t.Errorf("EncryptFhirConsent() error = %v", err)
			return
		}
		// decrypt the content for the custodian and compare
		result, err := cryptoClient.DecryptKeyAndCipherTextFor(types2.DoubleEncryptedCipherText{
			CipherText:     encryptedContent.CipherText,
			CipherTextKeys: [][]byte{encryptedContent.CipherTextKeys[0]},
			Nonce:          encryptedContent.Nonce,
		}, types2.LegalEntity{URI: custodianId},
		)
		if err != nil {
			t.Error("Error while decrypting text:", err)
		}
		if string(result) != string(validConsent) {
			t.Errorf("Decrypting content failed. Got: %v, wanted: %v", result, string(validConsent))
		}
	})
}

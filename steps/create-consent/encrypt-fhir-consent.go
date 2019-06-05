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
	"fmt"
	"github.com/labstack/gommon/log"
	"github.com/nuts-foundation/nuts-consent-logic/pkg"
	cryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg"
	cryptoEngine "github.com/nuts-foundation/nuts-crypto/pkg/crypto"
	registryTypes "github.com/nuts-foundation/nuts-registry/pkg"
	"github.com/nuts-foundation/nuts-registry/pkg/registry"
)

func EncryptFhirConsent(registryClient registry.Client, fhirConsent string, request pkg.CreateConsentRequest) (cryptoTypes.DoubleEncryptedCipherText, error) {
	// list of PEM encoded pubic keys to encrypt the record
	var partyKeys []string


	for _, actor := range request.Actors {
		// get public key for actor
		organization, err := registryClient.OrganizationById(registryTypes.LegalEntity{URI: string(actor)})
		if err != nil {
			fmt.Printf("error while getting public key for actor: %v from registry: %v", actor, err)
		}
		pk := *organization.PublicKey
		log.Debug("pk:", pk)
		partyKeys = append(partyKeys, pk)
	}
	cClient := cryptoEngine.NewCryptoClient()
	return cClient.EncryptKeyAndPlainTextWith([]byte(fhirConsent), partyKeys)
}

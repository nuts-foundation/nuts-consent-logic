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

package pkg

import (
	"fmt"
	"github.com/labstack/gommon/log"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	cryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg/types"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
)

func EncryptFhirConsent(registryClient registry.RegistryClient, cryptoClient crypto.Client, fhirConsent string, request CreateConsentRequest) (cryptoTypes.DoubleEncryptedCipherText, error) {
	// list of PEM encoded pubic keys to encrypt the record
	var partyKeys []string


	for _, actor := range request.Actors {
		// get public key for actor
		organization, err := registryClient.OrganizationById(string(actor))
		if err != nil {
			log.Errorf("error while getting public key for actor: %v from registry: %v", actor, err)
			return cryptoTypes.DoubleEncryptedCipherText{}, err
		}
		if organization.PublicKey == nil {
			return cryptoTypes.DoubleEncryptedCipherText{}, fmt.Errorf("registry entry for organization %v does not contain a public key", actor)
		}
		pk := *organization.PublicKey
		log.Debug("pk:", pk)
		partyKeys = append(partyKeys, pk)
	}
	return cryptoClient.EncryptKeyAndPlainTextWith([]byte(fhirConsent), partyKeys)
}
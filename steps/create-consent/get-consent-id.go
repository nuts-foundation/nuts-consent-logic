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
	"encoding/hex"
	"github.com/nuts-foundation/nuts-consent-logic/pkg"
	cryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/crypto"
)

// GetConsentId returns the consentId corresponding to the combinations of the subject and the custodian
func GetConsentId(request pkg.CreateConsentRequest) (string, error) {
	cClient := crypto.NewCryptoClient()
	subject := request.Subject
	legalEntity := cryptoTypes.LegalEntity{URI: string(request.Custodian)}

	id, err := cClient.ExternalIdFor([]byte(subject), legalEntity)
	return hex.EncodeToString(id), err
}

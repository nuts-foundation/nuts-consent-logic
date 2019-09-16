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
	"encoding/hex"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	cryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg/types"
)

// GetConsentId returns the consentId corresponding to the combinations of the subject and the custodian
func GetConsentId(cClient crypto.Client, request CreateConsentRequest) (string, error) {
	subject := request.Subject
	legalEntity := cryptoTypes.LegalEntity{URI: string(request.Custodian)}

	// todo refactor
	id, err := cClient.ExternalIdFor(string(subject), string(request.Actor), legalEntity)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(id), err
}

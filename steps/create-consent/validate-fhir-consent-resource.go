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
	validationEngine "github.com/nuts-foundation/nuts-fhir-validation/pkg/engine"
)

func ValidateFhirConsentResource(consentResource string) (bool, error) {
	validationClient := validationEngine.NewValidationEngine()
	// Fixme: can be removed when the validation engine is a singleton like the crypto engine
	validationClient.Configure()

	valid, errors, err := validationClient.ValidateAgainstSchema([]byte(consentResource))
	if !valid {
		fmt.Println(errors, err)
	}
	return valid, err
}
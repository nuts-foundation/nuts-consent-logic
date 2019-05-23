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
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-consent-logic/generated"
	"github.com/nuts-foundation/nuts-consent-logic/steps/create-consent"
	"net/http"
)

// Handlers provides the implementation of the generated ServerInterface
type Handlers struct{}

// NutsConsentLogicCreateConsent Creates the consent FHIR resource, validate it and sends it to the consent-bridge.
func (Handlers) NutsConsentLogicCreateConsent(ctx echo.Context) error {
	createConsentRequest := new(generated.CreateConsentRequest)
	if err := ctx.Bind(createConsentRequest); err != nil {
		ctx.Logger().Error("Could not unmarshall json body:", err)
		return err
	}

	{
		if res, err := create_consent.CustodianIsKnown(*createConsentRequest); !res || err != nil {
			return ctx.JSON(http.StatusForbidden, "Custodian is not a known vendor")
		}
	}
	{
		if res, err := create_consent.GetConsentId(*createConsentRequest); res == "" || err != nil {
			return ctx.JSON(http.StatusBadRequest, "Could not create the consentId for this combination of subject and custodian")
		}
	}
	{
		if res, err := create_consent.CreateFhirConsentResource(*createConsentRequest); res == "" || err != nil {
			return ctx.JSON(http.StatusBadRequest, "Could not create the FHIR consent resource")
		}
	}

	return ctx.JSON(http.StatusOK, createConsentRequest)
}

// NutsConsentLogicValidateConsent gets called by the consent-bridge on a consent-request event. It validates the
// consent-request with several rules. If valid it signs the fhir-consent-resource for each vendor with its private key
// and responds with the signatures to the consent-bridge
func (Handlers) NutsConsentLogicValidateConsent(ctx echo.Context) error {
	panic("implement me")
}

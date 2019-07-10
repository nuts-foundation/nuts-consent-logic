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
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-consent-logic/pkg"
	"net/http"
	"time"
)

// Wrapper provides the implementation of the generated ServerInterface
type Wrapper struct {
	Cl *pkg.ConsentLogic
}

// NutsConsentLogicCreateConsent Creates the consent FHIR resource, validate it and sends it to the consent-bridge.
func (wrapper Wrapper) NutsConsentLogicCreateConsent(ctx echo.Context) error {
	createConsentApiRequest := &CreateConsentRequest{}
	if err := ctx.Bind(createConsentApiRequest); err != nil {
		ctx.Logger().Error("Could not unmarshal json body:", err)
		return err
	}

	nullTime := time.Time{}

	if createConsentApiRequest.Period.Start == nullTime {
		err := errors.New("Period.start time is required")
		ctx.Logger().Error(err)
		return err
	}

	createConsentRequest := apiRequest2Internal(*createConsentApiRequest)

	if err := wrapper.Cl.StartConsentFlow(createConsentRequest); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	return ctx.JSON(http.StatusAccepted, createConsentRequest)
}

// NutsConsentLogicValidateConsent gets called by the consent-bridge on a consent-request event. It validates the
// consent-request with several rules. If valid it signs the fhir-consent-resource for each vendor with its private key
// and responds with the signatures to the consent-bridge
func (Wrapper) NutsConsentLogicValidateConsent(ctx echo.Context) error {
	panic("implement me")
}

// Convert the public generated data type to the internal type.
// This abstraction makes the app more robust to api changes.
func apiRequest2Internal(apiRequest CreateConsentRequest) *pkg.CreateConsentRequest {
	//convert api type to internal type
	createConsentRequest := &pkg.CreateConsentRequest{}
	createConsentRequest.Custodian = pkg.IdentifierURI(apiRequest.Custodian)
	createConsentRequest.Subject = pkg.IdentifierURI(apiRequest.Subject)

	var performer pkg.IdentifierURI
	if apiRequest.Performer != nil {
		performer = pkg.IdentifierURI(*apiRequest.Performer)
		createConsentRequest.Performer = &performer
	}

	for _, actor := range apiRequest.Actors {
		createConsentRequest.Actors = append(createConsentRequest.Actors, pkg.IdentifierURI(actor))
	}

	if len(apiRequest.ConsentProof.Data) > 0 {
		consentProof := &pkg.EmbeddedData{
			ContentType: apiRequest.ConsentProof.ContentType,
			Data:        apiRequest.ConsentProof.ContentType,
		}
		createConsentRequest.ConsentProof = consentProof
	}

	if apiRequest.Period != nil {
		period := pkg.Period{Start: apiRequest.Period.Start, End: apiRequest.Period.End}
		createConsentRequest.Period = &period
	}
	return createConsentRequest
}

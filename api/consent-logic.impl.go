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
func (wrapper Wrapper) CreateConsent(ctx echo.Context) error {
	createConsentApiRequest := &CreateConsentRequest{}
	if err := ctx.Bind(createConsentApiRequest); err != nil {
		ctx.Logger().Error("Could not unmarshal json body:", err)
		return err
	}

	// Validate if the request has at least one record
	if len(createConsentApiRequest.Records) < 1 {
		err := errors.New("the consent requires at least one record")
		ctx.Logger().Error(err)
		return err
	}

	nullTime := time.Time{}
	for _, record := range createConsentApiRequest.Records {
		// Validate if each record has a valid period Start:

		if record.Period.Start == nullTime {
			err := errors.New("period.start time is required")
			ctx.Logger().Error(err)
			return err
		}

		// Validate if each record has a valid proof
		if record.ConsentProof.Data == "" || record.ConsentProof.ContentType == "" {
			err := errors.New("each consent record needs a valid proof")
			ctx.Logger().Error(err)
			return err
		}
	}

	createConsentRequest := apiRequest2Internal(*createConsentApiRequest)

	eventUUID, err := wrapper.Cl.StartConsentFlow(createConsentRequest)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	uuid := eventUUID.String()
	response := JobCreatedResponse{ResultCode: "OK", JobId: &uuid}

	return ctx.JSON(http.StatusAccepted, response)
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

	for _, record := range apiRequest.Records {
		newRecord := pkg.Record{}

		period := pkg.Period{Start: record.Period.Start, End: record.Period.End}
		newRecord.Period = &period

		consentProof := &pkg.EmbeddedData{
			ContentType: record.ConsentProof.ContentType,
			Data:        record.ConsentProof.ContentType,
		}
		newRecord.ConsentProof = consentProof
		createConsentRequest.Records = append(createConsentRequest.Records, newRecord)
	}
	createConsentRequest.Actor = pkg.IdentifierURI(apiRequest.Actor)

	return createConsentRequest
}

/*
 *  Nuts consent logic holds the logic for consent creation
 *  Copyright (C) 2019 Nuts community
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-consent-logic/pkg"
	core "github.com/nuts-foundation/nuts-go-core"
)

// Wrapper provides the implementation of the generated ServerInterface
type Wrapper struct {
	Cl *pkg.ConsentLogic
}

// NutsConsentLogicCreateConsent Creates the consent FHIR resource, validate it and sends it to the consent-bridge.
func (wrapper Wrapper) CreateOrUpdateConsent(ctx echo.Context) error {
	createConsentApiRequest := &CreateConsentRequest{}
	if err := ctx.Bind(createConsentApiRequest); err != nil {
		ctx.Logger().Error("Could not unmarshal json body:", err)
		return err
	}

	// Validate all required fields
	if createConsentApiRequest.Custodian == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "the consent requires a custodian")
	}

	if createConsentApiRequest.Subject == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "the consent requires a subject")
	}

	if createConsentApiRequest.Actor == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "the consent requires an actor")
	}

	if len(createConsentApiRequest.Records) < 1 {
		return echo.NewHTTPError(http.StatusBadRequest, "the consent requires at least one record")
	}

	nullTime := time.Time{}
	for _, record := range createConsentApiRequest.Records {
		// Validate if each record has a valid period Start:
		if record.Period.Start == nullTime {
			return echo.NewHTTPError(http.StatusBadRequest, "the consent record requires a period.start")
		}

		// Validate if each record has a valid proof
		if record.ConsentProof.Title == "" || record.ConsentProof.ID == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "the consent record requires a valid proof")
		}

		// Validate DataClass
		if len(record.DataClass) < 1 {
			return echo.NewHTTPError(http.StatusBadRequest, "the consent record requires at least one data class")
		}

		for _, dataClass := range record.DataClass {
			if dataClass == "" {
				return echo.NewHTTPError(http.StatusBadRequest, "a data class can not be empty")
			}
			expr := fmt.Sprintf("urn:oid:%s:", core.NutsConsentClassesOID)
			if strings.Index(string(dataClass), expr) == -1 {
				return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("a data class must start with %s", expr))
			}
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
	createConsentRequest := &pkg.CreateConsentRequest{
		Custodian: pkg.IdentifierURI(apiRequest.Custodian),
		Subject:   pkg.IdentifierURI(apiRequest.Subject),
		Actor:     pkg.IdentifierURI(apiRequest.Actor),
	}

	var performer pkg.IdentifierURI
	if apiRequest.Performer != nil {
		performer = pkg.IdentifierURI(*apiRequest.Performer)
		createConsentRequest.Performer = &performer
	}

	for _, record := range apiRequest.Records {
		newRecord := pkg.Record{
			PreviousRecordhash: record.PreviousRecordHash,
		}

		newRecord.Period = pkg.Period{Start: record.Period.Start, End: record.Period.End}

		consentProof := &pkg.DocumentReference{
			ID:          record.ConsentProof.ID,
			Title:       record.ConsentProof.Title,
			ContentType: record.ConsentProof.ContentType,
			URL:         record.ConsentProof.URL,
			Hash:        record.ConsentProof.Hash,
		}
		newRecord.ConsentProof = consentProof

		for _, dc := range record.DataClass {
			newRecord.DataClass = append(newRecord.DataClass, pkg.IdentifierURI(dc))
		}

		createConsentRequest.Records = append(createConsentRequest.Records, newRecord)
	}

	return createConsentRequest
}

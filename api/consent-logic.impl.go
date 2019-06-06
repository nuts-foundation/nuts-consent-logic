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
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-consent-logic/pkg"
	"github.com/nuts-foundation/nuts-consent-logic/steps/create-consent"
	cryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg/types"
	"github.com/nuts-foundation/nuts-registry/client"
	"net/http"
)

// Wrapper provides the implementation of the generated ServerInterface
type Wrapper struct {
	Cl *pkg.ConsentLogic
}

// NutsConsentLogicCreateConsent Creates the consent FHIR resource, validate it and sends it to the consent-bridge.
func (Wrapper) NutsConsentLogicCreateConsent(ctx echo.Context) error {
	createConsentApiRequest := new(CreateConsentRequest)
	if err := ctx.Bind(createConsentApiRequest); err != nil {
		ctx.Logger().Error("Could not unmarshall json body:", err)
		return err
	}

	//convert api type to internal type
	createConsentRequest := &pkg.CreateConsentRequest{}
	{
		createConsentRequest.Custodian = pkg.IdentifierURI(createConsentApiRequest.Custodian)
		createConsentRequest.Subject = pkg.IdentifierURI(createConsentApiRequest.Subject)
		performer := pkg.IdentifierURI(*createConsentApiRequest.Performer)
		createConsentRequest.Performer = &performer

		for _, actor := range createConsentApiRequest.Actors {
			createConsentRequest.Actors = append(createConsentRequest.Actors, pkg.IdentifierURI(actor))
		}

		consentProof := &pkg.EmbeddedData{
			ContentType: createConsentApiRequest.ConsentProof.ContentType,
			Data:        createConsentApiRequest.ConsentProof.ContentType,
		}
		createConsentRequest.ConsentProof = consentProof

		period := pkg.Period{Start: createConsentApiRequest.Period.Start, End: createConsentApiRequest.Period.End}
		createConsentRequest.Period = &period
	}

	var fhirConsent string
	var encryptedConsent cryptoTypes.DoubleEncryptedCipherText

	{
		if res, err := steps.CustodianIsKnown(*createConsentRequest); !res || err != nil {
			return ctx.JSON(http.StatusForbidden, "Custodian is not a known vendor")
		}
	}
	{
		if res, err := steps.GetConsentId(*createConsentRequest); res == "" || err != nil {
			fmt.Println(err)
			return ctx.JSON(http.StatusBadRequest, "Could not create the consentId for this combination of subject and custodian")
		}
	}
	{
		var err error
		if fhirConsent, err = steps.CreateFhirConsentResource(*createConsentRequest); fhirConsent == "" || err != nil {
			return ctx.JSON(http.StatusBadRequest, "Could not create the FHIR consent resource")
		}
	}
	{
		if validationResult, err := steps.ValidateFhirConsentResource(fhirConsent); !validationResult || err != nil {
			return ctx.JSON(http.StatusBadRequest, fmt.Sprintf("The generated FHIR consent resource is invalid: %v", err))
		}
	}
	{
		var err error
		registryClient := client.NewRegistryClient()
		if encryptedConsent, err = steps.EncryptFhirConsent(registryClient, fhirConsent, *createConsentRequest); err != nil {
			return ctx.JSON(http.StatusBadRequest, fmt.Sprintf("Could not encrypt consent resource for all involved parties: %v", err))
		}
		fmt.Println(encryptedConsent)
	}

	return ctx.JSON(http.StatusOK, createConsentRequest)
}

// NutsConsentLogicValidateConsent gets called by the consent-bridge on a consent-request event. It validates the
// consent-request with several rules. If valid it signs the fhir-consent-resource for each vendor with its private key
// and responds with the signatures to the consent-bridge
func (Wrapper) NutsConsentLogicValidateConsent(ctx echo.Context) error {
	panic("implement me")
}

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
	"errors"
	"fmt"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	cryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg/types"
	"github.com/nuts-foundation/nuts-registry/client"
	"github.com/nuts-foundation/nuts-registry/pkg"
	"sync"
)

type ConsentLogicConfig struct {
}

type ConsentLogicClient interface {
	StartConsentFlow(*CreateConsentRequest) error
}
type ConsentLogic struct {
	NutsRegistry pkg.RegistryClient
	NutsCrypto   crypto.Client
	Config       ConsentLogicConfig
}

var instance *ConsentLogic
var oneEngine sync.Once

func ConsentLogicInstance() *ConsentLogic {
	oneEngine.Do(func() {
		instance = &ConsentLogic{
		}
	})
	return instance
}

func (cl ConsentLogic) StartConsentFlow(createConsentRequest *CreateConsentRequest) error {
	var fhirConsent string
	var encryptedConsent cryptoTypes.DoubleEncryptedCipherText

	{
		if res, err := CustodianIsKnown(*createConsentRequest); !res || err != nil {
			//return ctx.JSON(http.StatusForbidden, "Custodian is not a known vendor")
			return errors.New("custodian is not a known vendor")
		}
	}
	{
		if res, err := GetConsentId(cl.NutsCrypto, *createConsentRequest); res == "" || err != nil {
			fmt.Println(err)
			return errors.New("could not create the consentId for this combination of subject and custodian")
		}
	}
	{
		var err error
		if fhirConsent, err = CreateFhirConsentResource(*createConsentRequest); fhirConsent == "" || err != nil {
			return errors.New("could not create the FHIR consent resource")
		}
	}
	{
		if validationResult, err := ValidateFhirConsentResource(fhirConsent); !validationResult || err != nil {
			return errors.New(fmt.Sprintf("the generated FHIR consent resource is invalid: %v", err))
		}
	}
	{
		var err error
		if encryptedConsent, err = EncryptFhirConsent(cl.NutsRegistry, cl.NutsCrypto, fhirConsent, *createConsentRequest); err != nil {
			errors.New(fmt.Sprintf("could not encrypt consent resource for all involved parties: %v", err))
		}
		fmt.Println(encryptedConsent)
	}

	return nil
}

func (ConsentLogic) Configure() error {
	return nil
}

func (cl *ConsentLogic) Start() error {
	cl.NutsCrypto = crypto.NewCryptoClient()
	cl.NutsRegistry = client.NewRegistryClient()
	return nil
}

func (ConsentLogic) Shutdown() error {
	// Stub
	return nil
}

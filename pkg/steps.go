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

package pkg

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/cbroglie/mustache"
	cryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg/types"
	validationEngine "github.com/nuts-foundation/nuts-fhir-validation/pkg"
)

// getConsentID returns the consentId corresponding to the combinations of the subject and the custodian
func (cl ConsentLogic) getConsentID(request CreateConsentRequest) (string, error) {
	subject := request.Subject
	legalEntity := cryptoTypes.LegalEntity{URI: string(request.Custodian)}

	// todo refactor
	id, err := cl.NutsCrypto.ExternalIdFor(string(subject), string(request.Actor), legalEntity)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(id), err
}

// getVersionID returns the correct version number for the given record. "1" for a new record and "old + 1" for an update
func (cl ConsentLogic) getVersionID(request CreateConsentRequest) (string, error) {
	return "1", nil
}

// custodianIsKnown checks if the custodian from the request is managed by this node.
// If not, the request cannot continue.
func (cl ConsentLogic) custodianIsKnown(request CreateConsentRequest) (bool, error) {
	if pkey, _ := cl.NutsCrypto.PublicKeyInPEM(cryptoTypes.LegalEntity{URI: string(request.Custodian)}); pkey == "" {
		return false, nil
	}
	return true, nil
}

func (cl ConsentLogic) validateFhirConsentResource(consentResource string) (bool, error) {
	validationClient := validationEngine.NewValidatorClient()

	valid, errors, err := validationClient.ValidateAgainstSchema([]byte(consentResource))
	if !valid {
		fmt.Println(errors, err)
		fmt.Print(consentResource)
	}
	return valid, err
}

func (cl ConsentLogic) encryptFhirConsent(fhirConsent string, request CreateConsentRequest) (cryptoTypes.DoubleEncryptedCipherText, error) {
	// list of PEM encoded pubic keys to encrypt the record
	var partyKeys []string

	// get public key for actor
	organization, err := cl.NutsRegistry.OrganizationById(string(request.Actor))
	if err != nil {
		logger().Errorf("error while getting public key for actor: %v from registry: %v", request.Actor, err)
		return cryptoTypes.DoubleEncryptedCipherText{}, err
	}
	if organization.PublicKey == nil {
		return cryptoTypes.DoubleEncryptedCipherText{}, fmt.Errorf("registry entry for organization %v does not contain a public key", request.Actor)
	}
	pk := *organization.PublicKey
	partyKeys = append(partyKeys, pk)

	// and custodian
	pk, err = cl.NutsCrypto.PublicKeyInPEM(cryptoTypes.LegalEntity{URI: string(request.Custodian)})
	if err != nil {
		logger().Errorf("error while getting public key for custodian: %v from crypto: %v", request.Custodian, err)
		return cryptoTypes.DoubleEncryptedCipherText{}, err
	}
	partyKeys = append(partyKeys, pk)

	return cl.NutsCrypto.EncryptKeyAndPlainTextWith([]byte(fhirConsent), partyKeys)
}

func valueFromUrn(urn string) string {
	segments := strings.Split(urn, ":")
	return segments[len(segments)-1]
}

func (cl ConsentLogic) createFhirConsentResource(custodian, actor, subject, performer IdentifierURI, record Record) (string, error) {

	var actorAgbs []string
	actorAgbs = append(actorAgbs, valueFromUrn(string(actor)))

	dataClasses := make([]map[string]string, len(record.DataClass))
	viewModel := map[string]interface{}{
		"subjectBsn":   valueFromUrn(string(subject)),
		"actorAgbs":    actorAgbs,
		"custodianAgb": valueFromUrn(string(custodian)),
		"period": map[string]string{
			"Start": record.Period.Start.Format(time.RFC3339),
		},
		"dataClass":   dataClasses,
		"lastUpdated": nutsTime.Now().Format(time.RFC3339),
		"versionId":   "1",
	}

	// split data class identifiers
	for i, dc := range record.DataClass {
		dataClasses[i] = make(map[string]string)
		sdc := string(dc)
		li := strings.LastIndex(sdc, ":")
		dataClasses[i]["system"] = sdc[0:li]
		dataClasses[i]["code"] = sdc[li+1:]
	}

	if record.ConsentProof != nil {
		viewModel["consentProof"] = derefPointers(record.ConsentProof)
	}

	if performer != "" {
		viewModel["performerId"] = valueFromUrn(string(performer))
	}

	periodEnd := record.Period.End
	if periodEnd != nil {
		(viewModel["period"].(map[string]string))["End"] = periodEnd.Format(time.RFC3339)
	}

	var (
		res string
		err error
	)
	if res, err = mustache.Render(template, viewModel); err != nil {
		// uh oh
		return "", err
	}

	// filter out last comma out [{},{},] since mustache templates cannot handle this:
	// https://stackoverflow.com/questions/6114435/in-mustache-templating-is-there-an-elegant-way-of-expressing-a-comma-separated-l
	re := regexp.MustCompile(`\},(\s*)]`)
	res = re.ReplaceAllString(res, `}$1]`)

	return cleanupJSON(res)
}

func derefPointers(docReference *DocumentReference) map[string]interface{} {
	m := map[string]interface{}{}

	if docReference == nil {
		return nil
	}

	m["Title"] = docReference.Title
	m["ID"] = docReference.ID

	if docReference.Hash != nil {
		m["Hash"] = *docReference.Hash
	}

	if docReference.ContentType != nil {
		m["ContentType"] = *docReference.ContentType
	}

	if docReference.URL != nil {
		m["URL"] = *docReference.URL
	}

	return m
}

// clean up the json hash
func cleanupJSON(value string) (string, error) {
	var parsedValue interface{}
	if err := json.Unmarshal([]byte(value), &parsedValue); err != nil {
		return "", err
	}
	cleanValue, err := json.Marshal(parsedValue)
	if err != nil {
		return "", err
	}
	return string(cleanValue), nil
}

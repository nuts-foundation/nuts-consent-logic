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
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/cznic/strutil"
	bridgeClient "github.com/nuts-foundation/consent-bridge-go-client/api"
	cStoreClient "github.com/nuts-foundation/nuts-consent-store/client"
	cStore "github.com/nuts-foundation/nuts-consent-store/pkg"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	cryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg/types"
	"github.com/nuts-foundation/nuts-registry/client"
	"github.com/nuts-foundation/nuts-registry/pkg"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"sync"
)

type ConsentLogicConfig struct {
}

type ConsentLogicClient interface {
	StartConsentFlow(*CreateConsentRequest) error
	HandleConsentRequest(string) error
}

type ConsentLogic struct {
	NutsRegistry     pkg.RegistryClient
	NutsCrypto       crypto.Client
	NutsConsentStore cStore.ConsentStoreClient
	Config           ConsentLogicConfig
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
	var err error
	var fhirConsent string
	var consentId string
	var encryptedConsent cryptoTypes.DoubleEncryptedCipherText

	{
		if res, err := CustodianIsKnown(*createConsentRequest); !res || err != nil {
			//return ctx.JSON(http.StatusForbidden, "Custodian is not a known vendor")
			return errors.New("custodian is not a known vendor")
		}
		logrus.Debug("Custodian is known")
	}
	{
		if consentId, err = GetConsentId(cl.NutsCrypto, *createConsentRequest); consentId == "" || err != nil {
			fmt.Println(err)
			return errors.New("could not create the consentId for this combination of subject and custodian")
		}
		logrus.Debug("ConsentId generated")
	}
	{
		if fhirConsent, err = CreateFhirConsentResource(*createConsentRequest); fhirConsent == "" || err != nil {
			return errors.New("could not create the FHIR consent resource")
		}
		logrus.Debug("FHIR resource created")
	}
	{
		if validationResult, err := ValidateFhirConsentResource(fhirConsent); !validationResult || err != nil {
			return errors.New(fmt.Sprintf("the generated FHIR consent resource is invalid: %v", err))
		}
		logrus.Debug("FHIR resource is valid")
	}
	{
		if encryptedConsent, err = EncryptFhirConsent(cl.NutsRegistry, cl.NutsCrypto, fhirConsent, *createConsentRequest); err != nil {
			return errors.New(fmt.Sprintf("could not encrypt consent resource for all involved parties: %v", err))
		}
		logrus.Debug("FHIR resource encrypted", encryptedConsent)
	}
	{
		ctx := context.Background()

		bc := bridgeClient.NewConsentBridgeClient()

		state := bridgeClient.NewConsentRequestState{
			Attachment: string(strutil.Base64Encode(encryptedConsent.CipherText)),
			ExternalId: consentId,
			Metadata: bridgeClient.Metadata{
				Domain: []bridgeClient.Domain{"medical"},
				Period: bridgeClient.Period{
					ValidFrom: createConsentRequest.Period.Start,
					ValidTo: createConsentRequest.Period.End,
				},
				SecureKey: bridgeClient.SymmetricKey{
					Alg: "AES_GCM", //todo hardcoded
					Iv: string(strutil.Base64Encode(encryptedConsent.Nonce)),
				},
				OrganisationSecureKeys: []bridgeClient.ASymmetricKey{},
			},
		}

		legalEnts := createConsentRequest.Actors
		legalEnts = append(legalEnts, createConsentRequest.Custodian)

		alg := "RSA-OAEP"
		for i := range encryptedConsent.CipherTextKeys {
			ctBase64 := string(strutil.Base64Encode(encryptedConsent.CipherTextKeys[i]))
			state.Metadata.OrganisationSecureKeys = append(state.Metadata.OrganisationSecureKeys, bridgeClient.ASymmetricKey{
				Alg: &alg,
				CipherText: &ctBase64,
				LegalEntity: bridgeClient.Identifier(legalEnts[i]),
			})
		}

		logrus.Debugf("Sending NewConsentRequest to bridge: %+v", state)

		if err := bc.NewConsentRequestState(ctx, state); err != nil {
			return errors.New(fmt.Sprintf("sending new consent request state failed: %v", err))
		}

		logrus.Debug("Consent request send")
	}

	return nil
}

// HandleConsentRequest auto-acks ConsentRequests with the missing signatures
func (cl ConsentLogic) HandleConsentRequest(consentRequestId string) error {
	// get from bridge
	crs, err := bridgeClient.NewConsentBridgeClient().GetConsentRequestStateById(context.Background(), consentRequestId)

	if err != nil {
		// have event-octopus handle redelivery or cancellation
		return err
	}

	logrus.Debugf("Handling ConsentRequestState: %v", crs)

	var missingSignatures []string
	var attSignatures map[string]bool

	for _, att := range crs.Signatures {
		attSignatures[string(att.LegalEntity)] = true
	}

	for _, ent := range crs.LegalEntities {
		if !attSignatures[string(ent)] {
			key, _ := cl.NutsCrypto.PublicKey(cryptoTypes.LegalEntity{URI: string(ent)})
			if len(key) != 0 {
				logrus.Debugf("ConsentRequestState with id %v is missing signature for legalEntity %v",crs.ConsentId, ent)
				missingSignatures = append(missingSignatures,string(ent))
			}
		}
	}

	// todo download, unzip, validate
	// update
	for _, att := range crs.Attachments {

		attBytes, err := bridgeClient.NewConsentBridgeClient().GetAttachmentBySecureHash(context.Background(), att)
		if err != nil {
			logrus.Errorf("Error in downloading attachment with hash [%s]: %v", att, err)
			continue
		}

		for _, ent := range missingSignatures {
			r := base64.NewDecoder(base64.StdEncoding, bytes.NewReader(attBytes))
			dec, err := ioutil.ReadAll(r)

			if err != nil {
				logrus.Errorf("Error in decoding base64 string: %v", err)
				continue
			}

			// todo Sign attachment not its ID
			sigBytes, err := cl.NutsCrypto.SignFor(dec, cryptoTypes.LegalEntity{URI: ent})

			if err != nil {
					logrus.Errorf("Error in signing bytes for %s: %v", ent, err)
				continue
			}

			pubKey, err := cl.NutsCrypto.PublicKey(cryptoTypes.LegalEntity{URI: ent})
			if err != nil {
				logrus.Errorf("Error in getting pubKey for %s: %v", ent, err)
				continue
			}

			sigBytes64 := bytes.NewBuffer([]byte{})
			w := base64.NewEncoder(base64.StdEncoding, sigBytes64)
			if _, err := w.Write(sigBytes); err != nil {
				if err != nil {
					logrus.Errorf("Error in encoding base64 string: %v", err)
					continue
				}
			}

			attSig := bridgeClient.PartyAttachmentSignature{
				LegalEntity: bridgeClient.Identifier(ent),
				Attachment: att,
				Signature: bridgeClient.SignatureWithKey{
					Data: sigBytes64.String(),
					PublicKey: pubKey,
				},
			}

			logrus.Debugf("Sending AcceptConsentRequest to bridge: %+v", attSig)

			bridgeClient.NewConsentBridgeClient().AcceptConsentRequestState(context.Background(), consentRequestId, attSig)
		}
	}


	return nil
}

func (ConsentLogic) Configure() error {
	return nil
}

func (cl *ConsentLogic) Start() error {
	cl.NutsCrypto = crypto.NewCryptoClient()
	cl.NutsRegistry = client.NewRegistryClient()
	cl.NutsConsentStore = cStoreClient.NewConsentStoreClient()
	return nil
}

func (ConsentLogic) Shutdown() error {
	// Stub
	return nil
}

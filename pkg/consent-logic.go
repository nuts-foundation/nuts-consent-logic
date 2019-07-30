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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cznic/strutil"
	bridgeClient "github.com/nuts-foundation/consent-bridge-go-client/api"
	cStoreClient "github.com/nuts-foundation/nuts-consent-store/client"
	cStore "github.com/nuts-foundation/nuts-consent-store/pkg"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	cryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg/types"
	eventClient "github.com/nuts-foundation/nuts-event-octopus/client"
	events "github.com/nuts-foundation/nuts-event-octopus/pkg"
	registryClient "github.com/nuts-foundation/nuts-registry/client"
	"github.com/nuts-foundation/nuts-registry/pkg"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"sync"
)

type ConsentLogicConfig struct {
}

type ConsentLogicClient interface {
	StartConsentFlow(*CreateConsentRequest) error
	HandleIncomingCordaEvent(*events.Event)
}

type ConsentLogic struct {
	NutsRegistry     pkg.RegistryClient
	NutsCrypto       crypto.Client
	NutsConsentStore cStore.ConsentStoreClient
	NutsEventOctopus events.EventOctopusClient
	Config           ConsentLogicConfig
	EventPublisher   events.IEventPublisher
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
		state := bridgeClient.NewConsentRequestState{
			Attachment: string(strutil.Base64Encode(encryptedConsent.CipherText)),
			ExternalId: consentId,
			Metadata: bridgeClient.Metadata{
				Domain: []bridgeClient.Domain{"medical"},
				Period: bridgeClient.Period{
					ValidFrom: createConsentRequest.Period.Start,
					ValidTo:   createConsentRequest.Period.End,
				},
				SecureKey: bridgeClient.SymmetricKey{
					Alg: "AES_GCM", //todo hardcoded
					Iv:  string(strutil.Base64Encode(encryptedConsent.Nonce)),
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
				Alg:         &alg,
				CipherText:  &ctBase64,
				LegalEntity: bridgeClient.Identifier(legalEnts[i]),
			})
		}

		sjs, err := json.Marshal(state)
		if err != nil {
			return fmt.Errorf("failed to marshall NewConsentRequest to json: %v", err)
		}
		bsjs := base64.StdEncoding.EncodeToString(sjs)

		logrus.Debugf("Marshalled NewConsentRequest for bridge with state: %+v", state)

		event := events.Event{
			Uuid:                 uuid.NewV4().String(),
			Name:                 events.EventConsentRequestConstructed,
			InitiatorLegalEntity: string(createConsentRequest.Custodian),
			RetryCount:           0,
			ExternalId:           consentId,
			Payload:              bsjs,
		}

		err = cl.EventPublisher.Publish(events.ChannelConsentRequest, event)
		if err != nil {
			return fmt.Errorf("error during publishing of event: %v", err)
		}

		logrus.Debugf("Published NewConsentRequest to bridge with event: %+v", event)
	}

	return nil
}

// HandleIncomingCordaEvent auto-acks ConsentRequests with the missing signatures
// * Get the consentRequestState by id from the consentBridge
// * For each legalEntity get its public key
func (cl ConsentLogic) HandleIncomingCordaEvent(event *events.Event) {
	logrus.Infof("received event %v", event)

	crs := bridgeClient.FullConsentRequestState{}
	if err := json.Unmarshal([]byte(event.Payload), &crs); err != nil {
		// have event-octopus handle redelivery or cancellation
		errorDescription := "Could not unmarshall event payload"
		event.Error = &errorDescription
		logrus.WithError(err).Error(errorDescription)
		cl.EventPublisher.Publish(events.ChannelConsentErrored, *event)
		return
	}

	// check if all parties signed all attachments, than this request can be finalized by the initiator
	if len(crs.Signatures) == len(crs.LegalEntities) {
		logrus.Debugf("Sending FinalizeRequest to bridge for UUID: %s", event.ConsentId)

		// are we the initiator? InitiatorLegalEntity is only set at the initiating node.
		if event.InitiatorLegalEntity != "" {
			// finalize!
			event.Name = events.EventAllSignaturesPresent
			cl.EventPublisher.Publish(events.ChannelConsentRequest, *event)
		}
		// stop the flow and return
		return
	}

	logrus.Debugf("Handling ConsentRequestState: %+v", crs)

	// find out which legal entity is ours and still needs signing? It can be more than one, but always take first one missing.
	legalEntityToSignFor := cl.findFirstEntityToSignFor(crs.Signatures, crs.LegalEntities)

	// is there work for us?
	if legalEntityToSignFor == "" {
		// nothing to sign for this node. We are done.
		return
	}

	// decrypt
	// =======
	encodedCipherText := crs.CipherText
	cipherText, err := base64.StdEncoding.DecodeString(encodedCipherText)
	// convert hex string of attachment to bytes
	if err != nil {
		errorDescription := "Error in converting base64 encoded attachment"
		event.Error = &errorDescription
		logrus.WithError(err).Error(errorDescription)
		cl.EventPublisher.Publish(events.ChannelConsentErrored, *event)
		return
	}
	fhirConsent, err := cl.decryptConsentRecord(cipherText, crs, legalEntityToSignFor)
	if err != nil {
		errorDescription := "Could not decrypt consent record"
		event.Error = &errorDescription
		logrus.WithError(err).Error(errorDescription)
		cl.EventPublisher.Publish(events.ChannelConsentErrored, *event)
		return
	}

	// validate
	// ========
	if validationResult, err := ValidateFhirConsentResource(fhirConsent); !validationResult || err != nil {
		errorDescription := "Consent record invalid"
		event.Error = &errorDescription
		logrus.WithError(err).Error(errorDescription)
		cl.EventPublisher.Publish(events.ChannelConsentErrored, *event)
	}

	// publish EventConsentRequestValid
	// ===========================
	event.Name = events.EventConsentRequestValid
	cl.EventPublisher.Publish(events.ChannelConsentRequest, *event)
}

func (cl ConsentLogic) decryptConsentRecord(cipherText []byte, crs bridgeClient.FullConsentRequestState, legalEntity string) (string, error) {
	var legalEntityKey string

	for _, value := range crs.Metadata.OrganisationSecureKeys {
		if value.LegalEntity == bridgeClient.Identifier(legalEntity) {
			legalEntityKey = *value.CipherText
		}
	}

	dect := cryptoTypes.DoubleEncryptedCipherText{
		CipherText:     cipherText,
		CipherTextKeys: [][]byte{[]byte(legalEntityKey)},
		Nonce:          []byte(crs.Metadata.SecureKey.Iv),
	}
	encodedConsentRecord, err := cl.NutsCrypto.DecryptKeyAndCipherTextFor(dect, cryptoTypes.LegalEntity{URI: legalEntity})
	if err != nil {
		logrus.WithError(err).Error("Could not decrypt consent record")
		return "", err
	}
	consentRecord, err := base64.StdEncoding.DecodeString(string(encodedConsentRecord))
	if err != nil {
		logrus.WithError(err).Error("Could not base64decode consent record")
		return "", err
	}

	return string(consentRecord), nil
}

func (cl ConsentLogic) findFirstEntityToSignFor(signatures []bridgeClient.PartyAttachmentSignature, identifiers []bridgeClient.Identifier) string {
	// fill map with signatures legalEntity for easy lookup
	attSignatures := make(map[string]bool)
	for _, att := range signatures {
		attSignatures[string(att.LegalEntity)] = true
	}

	// Find all LegalEntities managed by this node which still need a signature
	// for each legal entity...
	for _, ent := range identifiers {
		// ... check if it has already signed the request
		if !attSignatures[string(ent)] {
			// if not, if this node manages the public key, than it is our identity.
			key, _ := cl.NutsCrypto.PublicKey(cryptoTypes.LegalEntity{URI: string(ent)})
			if len(key) != 0 {
				// yes, so lets add it to the missingSignatures so we can sign it in the next step
				return string(ent)
			}
		}
	}
	return ""
}

func (ConsentLogic) Configure() error {
	return nil
}

func (cl *ConsentLogic) Start() error {
	cl.NutsCrypto = crypto.NewCryptoClient()
	cl.NutsRegistry = registryClient.NewRegistryClient()
	cl.NutsConsentStore = cStoreClient.NewConsentStoreClient()
	cl.NutsEventOctopus = eventClient.NewEventOctopusClient()
	publisher, err := cl.NutsEventOctopus.EventPublisher("consent-logic")
	if err != nil {
		logrus.WithError(err).Panic("Could not subscribe to event publisher")
	}
	cl.EventPublisher = publisher

	err = cl.NutsEventOctopus.Subscribe("consent-logic",
		events.ChannelConsentRequest,
		map[string]events.EventHandlerCallback{
			events.EventConsentRequestConstructed: cl.HandleIncomingCordaEvent,
		})
	if err != nil {
		panic(err)
	}

	return nil
}

func (ConsentLogic) Shutdown() error {
	// Stub
	return nil
}

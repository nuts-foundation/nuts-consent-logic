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
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	bridgeClient "github.com/nuts-foundation/consent-bridge-go-client/api"
	cStoreClient "github.com/nuts-foundation/nuts-consent-store/client"
	cStore "github.com/nuts-foundation/nuts-consent-store/pkg"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	cryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg/types"
	eventClient "github.com/nuts-foundation/nuts-event-octopus/client"
	events "github.com/nuts-foundation/nuts-event-octopus/pkg"
	pkg2 "github.com/nuts-foundation/nuts-fhir-validation/pkg"
	registryClient "github.com/nuts-foundation/nuts-registry/client"
	"github.com/nuts-foundation/nuts-registry/pkg"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"gopkg.in/thedevsaddam/gojsonq.v2"
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

func Logger() *logrus.Entry {
	return logrus.StandardLogger().WithField("module", "consent-logic")
}

func ConsentLogicInstance() *ConsentLogic {
	oneEngine.Do(func() {
		instance = &ConsentLogic{}
	})
	return instance
}

func (cl ConsentLogic) StartConsentFlow(createConsentRequest *CreateConsentRequest) error {
	event, err := cl.createNewConsentRequestEvent(createConsentRequest)
	if err != nil {
		return err
	}

	err = cl.EventPublisher.Publish(events.ChannelConsentRequest, *event)
	if err != nil {
		return fmt.Errorf("error during publishing of event: %v", err)
	}

	Logger().Debugf("Published NewConsentRequest to bridge with event: %+v", event)
	return nil
}

func (cl ConsentLogic) createNewConsentRequestEvent(createConsentRequest *CreateConsentRequest) (*events.Event, error) {
	var err error
	var fhirConsent string
	var consentId string
	var encryptedConsent cryptoTypes.DoubleEncryptedCipherText

	{
		if res, err := CustodianIsKnown(*createConsentRequest); !res || err != nil {
			//return ctx.JSON(http.StatusForbidden, "Custodian is not a known vendor")
			return nil, errors.New("custodian is not a known vendor")
		}
		Logger().Debug("Custodian is known")
	}
	{
		if consentId, err = GetConsentId(cl.NutsCrypto, *createConsentRequest); consentId == "" || err != nil {
			fmt.Println(err)
			// todo: report back the reason why the consentId could not be generated. Probably because the custodian is not managed by this node?
			return nil, errors.New("could not create the consentId for this combination of subject and custodian")
		}
		Logger().Debug("ConsentId generated")
	}
	{
		if fhirConsent, err = CreateFhirConsentResource(*createConsentRequest); fhirConsent == "" || err != nil {
			return nil, errors.New("could not create the FHIR consent resource")
		}
		Logger().Debug("FHIR resource created")
	}
	{
		if validationResult, err := ValidateFhirConsentResource(fhirConsent); !validationResult || err != nil {
			return nil, fmt.Errorf("the generated FHIR consent resource is invalid: %v", err)
		}
		Logger().Debug("FHIR resource is valid")
	}
	{
		if encryptedConsent, err = EncryptFhirConsent(cl.NutsRegistry, cl.NutsCrypto, fhirConsent, *createConsentRequest); err != nil {
			return nil, fmt.Errorf("could not encrypt consent resource for all involved parties: %v", err)
		}
		Logger().Debug("FHIR resource encrypted")
	}
	var legalEntities []bridgeClient.Identifier

	cipherText := base64.StdEncoding.EncodeToString(encryptedConsent.CipherText)

	bridgeMeta := bridgeClient.Metadata{
		Domain: []bridgeClient.Domain{"medical"},
		Period: bridgeClient.Period{
			ValidFrom: createConsentRequest.Period.Start,
			ValidTo:   createConsentRequest.Period.End,
		},
		SecureKey: bridgeClient.SymmetricKey{
			Alg: "AES_GCM", //todo: fix hardcoded alg
			Iv:  base64.StdEncoding.EncodeToString(encryptedConsent.Nonce),
		},
	}

	for _, entity := range createConsentRequest.Actors {
		legalEntities = append(legalEntities, bridgeClient.Identifier(entity))
	}
	legalEntities = append(legalEntities, bridgeClient.Identifier(createConsentRequest.Custodian))

	payloadData := bridgeClient.FullConsentRequestState{
		CipherText:    &cipherText,
		ConsentId:     bridgeClient.ConsentId{ExternalId: &consentId},
		LegalEntities: legalEntities,
		Metadata:      &bridgeMeta,
	}

	alg := "RSA-OAEP"
	for i := range encryptedConsent.CipherTextKeys {
		ctBase64 := base64.StdEncoding.EncodeToString(encryptedConsent.CipherTextKeys[i])
		payloadData.Metadata.OrganisationSecureKeys = append(payloadData.Metadata.OrganisationSecureKeys, bridgeClient.ASymmetricKey{
			Alg:         &alg,
			CipherText:  &ctBase64,
			LegalEntity: legalEntities[i],
		})
	}

	sjs, err := json.Marshal(payloadData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshall NewConsentRequest to json: %v", err)
	}
	bsjs := base64.StdEncoding.EncodeToString(sjs)

	//Logger().Debugf("Marshalled NewConsentRequest for bridge with state: %+v", payloadData)

	event := &events.Event{
		Uuid:                 uuid.NewV4().String(),
		Name:                 events.EventConsentRequestConstructed,
		InitiatorLegalEntity: string(createConsentRequest.Custodian),
		RetryCount:           0,
		ExternalId:           consentId,
		Payload:              bsjs,
	}
	return event, nil
}

// HandleIncomingCordaEvent auto-acks ConsentRequests with the missing signatures
// * Get the consentRequestState by id from the consentBridge
// * For each legalEntity get its public key
func (cl ConsentLogic) HandleIncomingCordaEvent(event *events.Event) {
	Logger().Infof("received event %v", event)

	crs := bridgeClient.FullConsentRequestState{}
	decodedPayload, err := base64.StdEncoding.DecodeString(event.Payload)
	if err != nil {
		errorDescription := "Could not base64 decode event payload"
		event.Error = &errorDescription
		Logger().WithError(err).Error(errorDescription)
		_ = cl.EventPublisher.Publish(events.ChannelConsentErrored, *event)
	}
	if err := json.Unmarshal(decodedPayload, &crs); err != nil {
		// have event-octopus handle redelivery or cancellation
		errorDescription := "Could not unmarshall event payload"
		event.Error = &errorDescription
		Logger().WithError(err).Error(errorDescription)
		_ = cl.EventPublisher.Publish(events.ChannelConsentErrored, *event)
		return
	}

	// check if all parties signed all attachments, than this request can be finalized by the initiator
	if len(crs.Signatures) == len(crs.LegalEntities) {
		Logger().Debugf("All signatures present for UUID: %s", event.ConsentId)
		// are we the initiator? InitiatorLegalEntity is only set at the initiating node.
		if event.InitiatorLegalEntity != "" {

			for _, signature := range crs.Signatures {
				publicKey := signature.Signature.PublicKey
				legalEntityId := signature.LegalEntity
				legalEntity, err := cl.NutsRegistry.OrganizationById(string(legalEntityId))
				if err != nil {
					errorMsg := fmt.Sprintf("Could not get organization public key for: %s, err: %v", legalEntityId, err)
					event.Error = &errorMsg
					Logger().Debug(errorMsg)
					_ = cl.EventPublisher.Publish(events.ChannelConsentRetry, *event)
					return
				}
				if legalEntity.PublicKey == nil || *legalEntity.PublicKey != publicKey {
					errorMsg := fmt.Sprintf("Publickey of organization %s does not match with signatures publickey", legalEntityId)
					Logger().Debug(errorMsg)
					Logger().Debugf("publicKey from registry: %s ", *legalEntity.PublicKey)
					Logger().Debugf("publicKey from signature: %s ", publicKey)
					event.Error = &errorMsg
					_ = cl.EventPublisher.Publish(events.ChannelConsentErrored, *event)
					return
				}
			}

			Logger().Debugf("Sending FinalizeRequest to bridge for UUID: %s", event.ConsentId)
			event.Name = events.EventAllSignaturesPresent
			_ = cl.EventPublisher.Publish(events.ChannelConsentRequest, *event)
		} else {
			Logger().Debug("This node is not the initiator. Lets wait for the initiator to broadcast EventAllSignaturesPresent")
		}
		return
	}

	Logger().Debugf("Handling ConsentRequestState: %+v", crs)

	// find out which legal entity is ours and still needs signing? It can be more than one, but always take first one missing.
	legalEntityToSignFor := cl.findFirstEntityToSignFor(crs.Signatures, crs.LegalEntities)

	// is there work for us?
	if legalEntityToSignFor == "" {
		// nothing to sign for this node. We are done.
		return
	}

	// decrypt
	// =======
	fhirConsent, err := cl.decryptConsentRecord(crs, legalEntityToSignFor)
	if err != nil {
		errorDescription := "Could not decrypt consent record"
		event.Error = &errorDescription
		Logger().WithError(err).Error(errorDescription)
		_ = cl.EventPublisher.Publish(events.ChannelConsentErrored, *event)
		return
	}

	// validate consent record
	// =======================
	if validationResult, err := ValidateFhirConsentResource(fhirConsent); !validationResult || err != nil {
		errorDescription := "Consent record invalid"
		event.Error = &errorDescription
		Logger().WithError(err).Error(errorDescription)
		_ = cl.EventPublisher.Publish(events.ChannelConsentErrored, *event)
	}

	// publish EventConsentRequestValid
	// ===========================
	event.Name = events.EventConsentRequestValid
	_ = cl.EventPublisher.Publish(events.ChannelConsentRequest, *event)
}

func (cl ConsentLogic) SignConsentRequest(event *events.Event) {
	var newEvent *events.Event
	var err error

	if newEvent, err = cl.signConsentRequest(*event); err != nil {
		errorMsg := fmt.Sprintf("could nog sign request %v", err)
		event.Error = &errorMsg
		_ = cl.EventPublisher.Publish(events.ChannelConsentErrored, *event)
	}
	newEvent.Name = events.EventAttachmentSigned
	_ = cl.EventPublisher.Publish(events.ChannelConsentRequest, *newEvent)
}

func (cl ConsentLogic) signConsentRequest(event events.Event) (*events.Event, error) {
	crs := bridgeClient.FullConsentRequestState{}
	decodedPayload, err := base64.StdEncoding.DecodeString(event.Payload)
	if err != nil {
		errorDescription := "Could not base64 decode event payload"
		event.Error = &errorDescription
		Logger().WithError(err).Error(errorDescription)
		return &event, nil
	}
	if err := json.Unmarshal(decodedPayload, &crs); err != nil {
		// have event-octopus handle redelivery or cancellation
		errorDescription := "Could not unmarshall event payload"
		event.Error = &errorDescription
		Logger().WithError(err).Error(errorDescription)
		return &event, nil
	}
	legalEntityToSignFor := cl.findFirstEntityToSignFor(crs.Signatures, crs.LegalEntities)
	consentRecordHash := crs.AttachmentHashes[0]
	Logger().Debugf("signing for LegalEntity %s and consentRecordHash %s", legalEntityToSignFor, consentRecordHash)

	pubKey, err := cl.NutsCrypto.PublicKey(cryptoTypes.LegalEntity{URI: legalEntityToSignFor})
	if err != nil {
		Logger().Errorf("Error in getting pubKey for %s: %v", legalEntityToSignFor, err)
		return nil, err
	}
	hexConsentRecordHash, err := hex.DecodeString(consentRecordHash)
	if err != nil {
		Logger().Errorf("Could not decode consentRecordHash into hex value %s: %v", consentRecordHash, err)
		return nil, err
	}
	sigBytes, err := cl.NutsCrypto.SignFor(hexConsentRecordHash, cryptoTypes.LegalEntity{URI: legalEntityToSignFor})
	if err != nil {
		errorDescription := fmt.Sprintf("Could not sign consent record for %s, err: %v", legalEntityToSignFor, err)
		event.Error = &errorDescription
		Logger().WithError(err).Error(errorDescription)
		return &event, err
	}
	encodedSignatureBytes := base64.StdEncoding.EncodeToString(sigBytes)
	partySignature := bridgeClient.PartyAttachmentSignature{
		Attachment:  consentRecordHash,
		LegalEntity: bridgeClient.Identifier(legalEntityToSignFor),
		Signature: bridgeClient.SignatureWithKey{
			Data:      encodedSignatureBytes,
			PublicKey: pubKey,
		},
	}

	payload, err := json.Marshal(partySignature)
	if err != nil {
		return nil, err
	}
	event.Payload = base64.StdEncoding.EncodeToString(payload)
	Logger().Debugf("Consent request signed for %s", legalEntityToSignFor)

	return &event, nil
}

func (cl ConsentLogic) decryptConsentRecord(crs bridgeClient.FullConsentRequestState, legalEntity string) (string, error) {
	encodedCipherText := crs.CipherText
	cipherText, err := base64.StdEncoding.DecodeString(*encodedCipherText)
	// convert hex string of attachment to bytes
	if err != nil {
		return "", err
	}

	if crs.Metadata == nil {
		err := errors.New("missing metadata in consentRequest")
		Logger().Error(err)
		return "", err
	}

	var encodedLegalEntityKey string
	for _, value := range crs.Metadata.OrganisationSecureKeys {
		if value.LegalEntity == bridgeClient.Identifier(legalEntity) {
			encodedLegalEntityKey = *value.CipherText
		}
	}

	if encodedLegalEntityKey == "" {
		return "", fmt.Errorf("no key found for legalEntity: %s", legalEntity)
	}
	legalEntityKey, _ := base64.StdEncoding.DecodeString(encodedLegalEntityKey)

	nonce, _ := base64.StdEncoding.DecodeString(crs.Metadata.SecureKey.Iv)
	dect := cryptoTypes.DoubleEncryptedCipherText{
		CipherText:     cipherText,
		CipherTextKeys: [][]byte{legalEntityKey},
		Nonce:          nonce,
	}
	consentRecord, err := cl.NutsCrypto.DecryptKeyAndCipherTextFor(dect, cryptoTypes.LegalEntity{URI: legalEntity})
	if err != nil {
		Logger().WithError(err).Error("Could not decrypt consent record")
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
				Logger().Debugf("found first entity to sign for: %v", ent)
				return string(ent)
			}
		}
	}
	return ""
}

// AutoAckConsentRequest republishes every event as acked.
// TODO: This should be made optional so the ECD can perform checks and publish the ack or nack
func (cl ConsentLogic) AutoAckConsentRequest(event *events.Event) {
	event, _ = cl.autoAckConsentRequest(*event)
	_ = cl.EventPublisher.Publish(events.ChannelConsentRequest, *event)
}

func (cl ConsentLogic) autoAckConsentRequest(event events.Event) (*events.Event, error) {
	newEvent := event
	newEvent.Name = events.EventConsentRequestAcked
	return &newEvent, nil
}

func (cl ConsentLogic) StoreConsent(event *events.Event) {
	crs := bridgeClient.FullConsentRequestState{}
	decodedPayload, err := base64.StdEncoding.DecodeString(event.Payload)
	if err != nil {
		Logger().Errorf("Unable to base64 decode event payload")
		return
	}
	if err := json.Unmarshal(decodedPayload, &crs); err != nil {
		Logger().Errorf("Unable to unmarshal event payload")
		return
	}

	var consentRules []cStore.ConsentRule

	for _, actor := range crs.LegalEntities {
		publicKey, err := cl.NutsCrypto.PublicKey(cryptoTypes.LegalEntity{URI: string(actor)})
		if err != nil || publicKey == "" {
			// this actor is not managed by this node, try with next
			continue
		}

		fhirConsentString, err := cl.decryptConsentRecord(crs, string(actor))
		if err != nil {
			Logger().Error("Could not decrypt fhir consent")
			return
		}

		// todo: check everything for validity again
		consentRules = cl.ConsentRulesFromFHIRRecord(fhirConsentString)

		// consentrules gathered, continue with the flow
		break
	}

	consentRules = cl.filterConssentRules(consentRules)

	Logger().Debugf("Storing consent: %+v", consentRules)
	cl.NutsConsentStore.RecordConsent(context.Background(), consentRules)

	event.Name = events.EventCompleted
	cl.EventPublisher.Publish(events.ChannelConsentRequest, *event)
}

// only consent records of which or the custodian or the actor is managed by this node should be stored
func (cl ConsentLogic)filterConssentRules(allRules []cStore.ConsentRule) []cStore.ConsentRule {
	var validRules []cStore.ConsentRule
	for _, rule := range allRules {
		// add if custodian is managed by this node
		if key, _ := cl.NutsCrypto.PublicKey(cryptoTypes.LegalEntity{URI:rule.Custodian});  key != "" {
			validRules = append(validRules, rule)
			continue
		}
		// or if the actor is managed by this node
		if key, _ := cl.NutsCrypto.PublicKey(cryptoTypes.LegalEntity{URI:rule.Actor}); key != "" {
			validRules = append(validRules, rule)
			continue
		}
	}

	return validRules
}

func (ConsentLogic) ConsentRulesFromFHIRRecord(fhirConsentString string) ([]cStore.ConsentRule) {
	var consentRules []cStore.ConsentRule

	fhirConsent := gojsonq.New().JSONString(fhirConsentString)

	actors := pkg2.ActorsFrom(fhirConsent)
	custodian := pkg2.CustodianFrom(fhirConsent)
	subject := pkg2.SubjectFrom(fhirConsent)
	resources := cStore.ResourcesFromStrings(pkg2.ResourcesFrom(fhirConsent))

	for _, actor := range actors {
		consentRules = append(consentRules, cStore.ConsentRule{
			Actor:     string(actor),
			Custodian: custodian,
			Resources: resources,
			Subject:   subject,
		})
	}

	return consentRules
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
		Logger().WithError(err).Panic("Could not subscribe to event publisher")
	}
	cl.EventPublisher = publisher

	err = cl.NutsEventOctopus.Subscribe("consent-logic",
		events.ChannelConsentRequest,
		map[string]events.EventHandlerCallback{
			events.EventDistributedConsentRequestReceived: cl.HandleIncomingCordaEvent,
			events.EventConsentRequestValid:               cl.AutoAckConsentRequest,
			events.EventConsentRequestAcked:               cl.SignConsentRequest,
			events.EventConsentDistributed:                cl.StoreConsent,
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

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
	StartConsentFlow(*CreateConsentRequest) (*uuid.UUID, error)
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

func logger() *logrus.Entry {
	return logrus.StandardLogger().WithField("module", "consent-logic")
}

func ConsentLogicInstance() *ConsentLogic {
	oneEngine.Do(func() {
		instance = &ConsentLogic{}
	})
	return instance
}

// StartConsentFlow is the start of the consentFlow. It is a a blocking method which will fire the first event.
func (cl ConsentLogic) StartConsentFlow(createConsentRequest *CreateConsentRequest) (*uuid.UUID, error) {
	event, err := cl.createNewConsentRequestEvent(createConsentRequest)
	if err != nil {
		return nil, err
	}

	err = cl.EventPublisher.Publish(events.ChannelConsentRequest, *event)
	if err != nil {
		return nil, err
	}
	eventUUID, err := uuid.FromString(event.Uuid)
	if err != nil {
		return nil, err
	}

	logger().Debugf("Published NewConsentRequest to bridge with event: %+v", event)
	return &eventUUID, nil
}

func (cl ConsentLogic) createNewConsentRequestEvent(createConsentRequest *CreateConsentRequest) (*events.Event, error) {
	var err error
	var consentID string
	records := []bridgeClient.ConsentRecord{}
	var legalEntities []bridgeClient.Identifier

	{
		if res, err := CustodianIsKnown(cl.NutsCrypto, *createConsentRequest); !res || err != nil {
			return nil, errors.New("custodian is not a known vendor")
		}
		logger().Debug("Custodian is known")
	}
	{
		if consentID, err = GetConsentId(cl.NutsCrypto, *createConsentRequest); consentID == "" || err != nil {
			fmt.Println(err)
			// todo: report back the reason why the consentID could not be generated. Probably because the custodian is not managed by this node?
			return nil, errors.New("could not create the consentID for this combination of subject, actor and custodian")
		}
		logger().Debug("ConsentId generated")
	}

	legalEntities = append(legalEntities, bridgeClient.Identifier(createConsentRequest.Actor))
	legalEntities = append(legalEntities, bridgeClient.Identifier(createConsentRequest.Custodian))

	for _, record := range createConsentRequest.Records {
		var fhirConsent string
		var encryptedConsent cryptoTypes.DoubleEncryptedCipherText
		{
			if fhirConsent, err = CreateFhirConsentResource(createConsentRequest.Custodian, createConsentRequest.Actor, createConsentRequest.Subject, *createConsentRequest.Performer, record); fhirConsent == "" || err != nil {
				return nil, errors.New("could not create the FHIR consent resource")
			}
			logger().Debug("FHIR resource created", fhirConsent)
		}
		{
			if validationResult, err := ValidateFhirConsentResource(fhirConsent); !validationResult || err != nil {
				return nil, fmt.Errorf("the generated FHIR consent resource is invalid: %v", err)
			}
			logger().Debug("FHIR resource is valid")
		}
		{
			if encryptedConsent, err = EncryptFhirConsent(cl.NutsRegistry, cl.NutsCrypto, fhirConsent, *createConsentRequest); err != nil {
				return nil, fmt.Errorf("could not encrypt consent resource for all involved parties: %v", err)
			}
			logger().Debug("FHIR resource encrypted")
		}

		cipherText := base64.StdEncoding.EncodeToString(encryptedConsent.CipherText)

		bridgeMeta := bridgeClient.Metadata{
			Domain: []bridgeClient.Domain{"medical"},
			Period: bridgeClient.Period{
				ValidFrom: record.Period.Start,
				ValidTo:   record.Period.End,
			},
			SecureKey: bridgeClient.SymmetricKey{
				Alg: "AES_GCM", //todo: fix hardcoded alg
				Iv:  base64.StdEncoding.EncodeToString(encryptedConsent.Nonce),
			},
		}

		alg := "RSA-OAEP"
		for i := range encryptedConsent.CipherTextKeys {
			ctBase64 := base64.StdEncoding.EncodeToString(encryptedConsent.CipherTextKeys[i])
			bridgeMeta.OrganisationSecureKeys = append(bridgeMeta.OrganisationSecureKeys, bridgeClient.ASymmetricKey{
				Alg:         &alg,
				CipherText:  &ctBase64,
				LegalEntity: legalEntities[i],
			})
		}

		records = append(records, bridgeClient.ConsentRecord{Metadata: &bridgeMeta, CipherText: &cipherText})
	}

	// The eventID is used to follow all the events. The created corda state-branch also gets this id.
	eventID := uuid.NewV4().String()

	payloadData := bridgeClient.FullConsentRequestState{
		ConsentId:      bridgeClient.ConsentId{ExternalId: &consentID, UUID: eventID},
		LegalEntities:  legalEntities,
		ConsentRecords: records,
	}

	sjs, err := json.Marshal(payloadData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshall NewConsentRequest to json: %v", err)
	}
	bsjs := base64.StdEncoding.EncodeToString(sjs)

	event := &events.Event{
		Uuid:                 eventID,
		Name:                 events.EventConsentRequestConstructed,
		InitiatorLegalEntity: string(createConsentRequest.Custodian),
		RetryCount:           0,
		ExternalId:           consentID,
		Payload:              bsjs,
	}
	return event, nil
}

// HandleIncomingCordaEvent auto-acks ConsentRequests with the missing signatures
// * Get the consentRequestState by id from the consentBridge
// * For each legalEntity get its public key
func (cl ConsentLogic) HandleIncomingCordaEvent(event *events.Event) {
	logger().Infof("received event %v", event)

	crs := bridgeClient.FullConsentRequestState{}
	decodedPayload, err := base64.StdEncoding.DecodeString(event.Payload)
	if err != nil {
		errorDescription := "Could not base64 decode event payload"
		event.Error = &errorDescription
		logger().WithError(err).Error(errorDescription)
		_ = cl.EventPublisher.Publish(events.ChannelConsentErrored, *event)
	}
	if err := json.Unmarshal(decodedPayload, &crs); err != nil {
		// have event-octopus handle redelivery or cancellation
		errorDescription := "Could not unmarshall event payload"
		event.Error = &errorDescription
		logger().WithError(err).Error(errorDescription)
		_ = cl.EventPublisher.Publish(events.ChannelConsentErrored, *event)
		return
	}

	// check if all parties signed all attachments, than this request can be finalized by the initiator
	allSigned := true
	for _, cr := range crs.ConsentRecords {
		if cr.Signatures == nil || len(*cr.Signatures) != len(crs.LegalEntities) {
			allSigned = false
		}
	}

	if allSigned {
		logger().Debugf("All signatures present for UUID: %s", event.ConsentId)
		// Is this node the initiator? InitiatorLegalEntity is only set at the initiating node.
		if event.InitiatorLegalEntity != "" {

			// Now check the public keys used by the signatures
			for _, cr := range crs.ConsentRecords {
				for _, signature := range *cr.Signatures {
					// Get the published public key from register
					legalEntityID := signature.LegalEntity
					legalEntity, err := cl.NutsRegistry.OrganizationById(string(legalEntityID))
					if err != nil {
						errorMsg := fmt.Sprintf("Could not get organization public key for: %s, err: %v", legalEntityID, err)
						event.Error = &errorMsg
						logger().Debug(errorMsg)
						_ = cl.EventPublisher.Publish(events.ChannelConsentRetry, *event)
						return
					}
					publicKey := signature.Signature.PublicKey
					// Check if the signatures public key equals the published key
					// TODO: This uses a single public key per legalEntity. When key rotation comes into play, fix this
					if legalEntity.PublicKey == nil || *legalEntity.PublicKey != publicKey {
						errorMsg := fmt.Sprintf("Publickey of organization %s does not match with signatures publickey", legalEntityID)
						logger().Debug(errorMsg)
						logger().Debugf("publicKey from registry: %s ", *legalEntity.PublicKey)
						logger().Debugf("publicKey from signature: %s ", publicKey)
						event.Error = &errorMsg
						_ = cl.EventPublisher.Publish(events.ChannelConsentErrored, *event)
						return
					}

					// checking the actual signature here is not required since it's already checked by the CordApp.
				}
			}

			logger().Debugf("Sending FinalizeRequest to bridge for UUID: %s", event.ConsentId)
			event.Name = events.EventAllSignaturesPresent
			_ = cl.EventPublisher.Publish(events.ChannelConsentRequest, *event)
		} else {
			logger().Debug("This node is not the initiator. Lets wait for the initiator to broadcast EventAllSignaturesPresent")
		}
		return
	}

	logger().Debugf("Handling ConsentRequestState: %+v", crs)

	for _, cr := range crs.ConsentRecords {
		// find out which legal entity is ours and still needs signing? It can be more than one, but always take first one missing.
		legalEntityToSignFor := cl.findFirstEntityToSignFor(cr.Signatures, crs.LegalEntities)

		// is there work for us?
		if legalEntityToSignFor == "" {
			// nothing to sign for this node/record.
			continue
		}

		// decrypt
		// =======
		fhirConsent, err := cl.decryptConsentRecord(cr, legalEntityToSignFor)
		if err != nil {
			errorDescription := "Could not decrypt consent record"
			event.Error = &errorDescription
			logger().WithError(err).Error(errorDescription)
			_ = cl.EventPublisher.Publish(events.ChannelConsentErrored, *event)
			return
		}

		// validate consent record
		// =======================
		if validationResult, err := ValidateFhirConsentResource(fhirConsent); !validationResult || err != nil {
			errorDescription := "Consent record invalid"
			event.Error = &errorDescription
			logger().WithError(err).Error(errorDescription)
			_ = cl.EventPublisher.Publish(events.ChannelConsentErrored, *event)
		}

		// publish EventConsentRequestValid
		// ===========================
		event.Name = events.EventConsentRequestValid
		_ = cl.EventPublisher.Publish(events.ChannelConsentRequest, *event)
	}
}

// HandleEventConsentRequestAcked handles the Event Consent Request Acked event. It passes a copy of the event to the
// signing step and if everything is ok, it publishes this new event to ChannelConsentRequest.
// In case of an error, it publishes the event to ChannelConsentErrored.
func (cl ConsentLogic) HandleEventConsentRequestAcked(event *events.Event) {
	var newEvent *events.Event
	var err error

	if newEvent, err = cl.signConsentRequest(*event); err != nil {
		errorMsg := fmt.Sprintf("could not sign request %v", err)
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
		logger().WithError(err).Error(errorDescription)
		return &event, nil
	}
	if err := json.Unmarshal(decodedPayload, &crs); err != nil {
		// have event-octopus handle redelivery or cancellation
		errorDescription := "Could not unmarshall event payload"
		event.Error = &errorDescription
		logger().WithError(err).Error(errorDescription)
		return &event, nil
	}

	for _, cr := range crs.ConsentRecords {
		legalEntityToSignFor := cl.findFirstEntityToSignFor(cr.Signatures, crs.LegalEntities)

		// is there work for the given record, otherwise continue till a missing signature is detected
		if legalEntityToSignFor == "" {
			// nothing to sign for this node/record.
			continue
		}

		consentRecordHash := *cr.AttachmentHash
		logger().Debugf("signing for LegalEntity %s and consentRecordHash %s", legalEntityToSignFor, consentRecordHash)

		pubKey, err := cl.NutsCrypto.PublicKey(cryptoTypes.LegalEntity{URI: legalEntityToSignFor})
		if err != nil {
			logger().Errorf("Error in getting pubKey for %s: %v", legalEntityToSignFor, err)
			return nil, err
		}
		hexConsentRecordHash, err := hex.DecodeString(consentRecordHash)
		if err != nil {
			logger().Errorf("Could not decode consentRecordHash into hex value %s: %v", consentRecordHash, err)
			return nil, err
		}
		sigBytes, err := cl.NutsCrypto.SignFor(hexConsentRecordHash, cryptoTypes.LegalEntity{URI: legalEntityToSignFor})
		if err != nil {
			errorDescription := fmt.Sprintf("Could not sign consent record for %s, err: %v", legalEntityToSignFor, err)
			event.Error = &errorDescription
			logger().WithError(err).Error(errorDescription)
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
		logger().Debugf("Consent request signed for %s", legalEntityToSignFor)

		return &event, nil
	}

	errorDescription := fmt.Sprintf("event with name %s recevied, but nothing to sign for this node", events.EventConsentRequestValid)
	event.Error = &errorDescription
	logger().WithError(err).Error(errorDescription)
	return &event, err
}

func (cl ConsentLogic) decryptConsentRecord(cr bridgeClient.ConsentRecord, legalEntity string) (string, error) {
	encodedCipherText := cr.CipherText
	cipherText, err := base64.StdEncoding.DecodeString(*encodedCipherText)
	// convert hex string of attachment to bytes
	if err != nil {
		return "", err
	}

	if cr.Metadata == nil {
		err := errors.New("missing metadata in consentRequest")
		logger().Error(err)
		return "", err
	}

	var encodedLegalEntityKey string
	for _, value := range cr.Metadata.OrganisationSecureKeys {
		if value.LegalEntity == bridgeClient.Identifier(legalEntity) {
			encodedLegalEntityKey = *value.CipherText
		}
	}

	if encodedLegalEntityKey == "" {
		return "", fmt.Errorf("no key found for legalEntity: %s", legalEntity)
	}
	legalEntityKey, _ := base64.StdEncoding.DecodeString(encodedLegalEntityKey)

	nonce, _ := base64.StdEncoding.DecodeString(cr.Metadata.SecureKey.Iv)
	dect := cryptoTypes.DoubleEncryptedCipherText{
		CipherText:     cipherText,
		CipherTextKeys: [][]byte{legalEntityKey},
		Nonce:          nonce,
	}
	consentRecord, err := cl.NutsCrypto.DecryptKeyAndCipherTextFor(dect, cryptoTypes.LegalEntity{URI: legalEntity})
	if err != nil {
		logger().WithError(err).Error("Could not decrypt consent record")
		return "", err
	}

	return string(consentRecord), nil
}

// The node can manage more than one legalEntity. This method provides a deterministic way of selecting the current
// legalEntity to work with. It loops over all legalEntities, selects the ones that still needs to sign and selects
// the first one which is managed by this node.
func (cl ConsentLogic) findFirstEntityToSignFor(signatures *[]bridgeClient.PartyAttachmentSignature, identifiers []bridgeClient.Identifier) string {
	// fill map with signatures legalEntity for easy lookup
	attSignatures := make(map[string]bool)
	// signatures can be nil if no signatures have been set yet
	if signatures != nil {
		for _, att := range *signatures {
			attSignatures[string(att.LegalEntity)] = true
		}

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
				logger().Debugf("found first entity to sign for: %v", ent)
				return string(ent)
			}
		}
	}
	return ""
}

// HandleEventConsentRequestValid republishes every event as acked.
// TODO: This should be made optional so the ECD can perform checks and publish the ack or nack
func (cl ConsentLogic) HandleEventConsentRequestValid(event *events.Event) {
	event, _ = cl.autoAckConsentRequest(*event)
	_ = cl.EventPublisher.Publish(events.ChannelConsentRequest, *event)
}

func (cl ConsentLogic) autoAckConsentRequest(event events.Event) (*events.Event, error) {
	newEvent := event
	newEvent.Name = events.EventConsentRequestAcked
	return &newEvent, nil
}

// HandleEventConsentDistributed handles EventConsentDistributed.
// This is the final step in the distributed consent state-machine.
// It decodes the payload, performs final tests and stores the relevant consentRules in the consent-store.
func (cl ConsentLogic) HandleEventConsentDistributed(event *events.Event) {
	crs := bridgeClient.ConsentState{}
	decodedPayload, err := base64.StdEncoding.DecodeString(event.Payload)
	if err != nil {
		logger().Errorf("Unable to base64 decode event payload")
		return
	}
	if err := json.Unmarshal(decodedPayload, &crs); err != nil {
		logger().Errorf("Unable to unmarshal event payload")
		return
	}

	var patientConsents []cStore.PatientConsent

	for _, cr := range crs.ConsentRecords {
		for _, organisation := range cr.Metadata.OrganisationSecureKeys {
			publicKey, err := cl.NutsCrypto.PublicKey(cryptoTypes.LegalEntity{URI: string(organisation.LegalEntity)})
			if err != nil || publicKey == "" {
				// this organisation is not managed by this node, try with next
				continue
			}

			fhirConsentString, err := cl.decryptConsentRecord(cr, string(organisation.LegalEntity))
			if err != nil {
				logger().Error("Could not decrypt fhir consent")
				return
			}

			patientConsent := cl.PatientConsentFromFHIRRecord(fhirConsentString)
			patientConsent.ID = *crs.ConsentId.ExternalId
			patientConsent.Records[0].Hash = *cr.AttachmentHash
			patientConsents = append(patientConsents, patientConsent)

			// todo: check the contents of the patientConsent for validity since the other side might have changed it

			// consentrules gathered, continue with the flow
			break
		}
	}

	patientConsents = cl.filterConsentRules(patientConsents)
	logger().Debugf("found %d consent rules", len(patientConsents))

	logger().Debugf("Storing consent: %+v", patientConsents)
	err = cl.NutsConsentStore.RecordConsent(context.Background(), patientConsents)
	if err != nil {
		logger().WithError(err).Error("unable to record the consents")
		return
	}

	event.Name = events.EventCompleted
	err = cl.EventPublisher.Publish(events.ChannelConsentRequest, *event)
	if err != nil {
		logger().WithError(err).Error("unable to publish the EventCompleted event")
		return
	}
}

// only consent records of which or the custodian or the actor is managed by this node should be stored
func (cl ConsentLogic) filterConsentRules(allRules []cStore.PatientConsent) []cStore.PatientConsent {
	var validRules []cStore.PatientConsent
	for _, rule := range allRules {
		// add if custodian is managed by this node
		if key, _ := cl.NutsCrypto.PublicKey(cryptoTypes.LegalEntity{URI: rule.Custodian}); key != "" {
			validRules = append(validRules, rule)
			continue
		}
		// or if the actor is managed by this node
		if key, _ := cl.NutsCrypto.PublicKey(cryptoTypes.LegalEntity{URI: rule.Actor}); key != "" {
			validRules = append(validRules, rule)
			continue
		}
	}

	return validRules
}

// PatientConsentFromFHIRRecord extracts the PatientConsent from a FHIR consent record encoded as json string.
func (ConsentLogic) PatientConsentFromFHIRRecord(fhirConsentString string) cStore.PatientConsent {
	fhirConsent := gojsonq.New().JSONString(fhirConsentString)

	actor := pkg2.ActorsFrom(fhirConsent)[0]
	custodian := pkg2.CustodianFrom(fhirConsent)
	subject := pkg2.SubjectFrom(fhirConsent)
	resources := cStore.ResourcesFromStrings(pkg2.ResourcesFrom(fhirConsent))
	period := pkg2.PeriodFrom(fhirConsent)
	record := []cStore.ConsentRecord{{Resources: resources, ValidFrom: period[0], ValidTo: period[1]}}

	return cStore.PatientConsent{
		Actor:     string(actor),
		Custodian: custodian,
		Subject:   subject,
		Records:   record,
	}
}

func (ConsentLogic) Configure() error {
	return nil
}

// Start starts a new ConsentLogic engine. It populates the ConsentLogic struct with client from other engines and
// subscribes to nats.io event.
func (cl *ConsentLogic) Start() error {
	cl.NutsCrypto = crypto.NewCryptoClient()
	cl.NutsRegistry = registryClient.NewRegistryClient()
	cl.NutsConsentStore = cStoreClient.NewConsentStoreClient()
	cl.NutsEventOctopus = eventClient.NewEventOctopusClient()
	publisher, err := cl.NutsEventOctopus.EventPublisher("consent-logic")
	if err != nil {
		logger().WithError(err).Panic("Could not subscribe to event publisher")
	}
	cl.EventPublisher = publisher

	err = cl.NutsEventOctopus.Subscribe("consent-logic",
		events.ChannelConsentRequest,
		map[string]events.EventHandlerCallback{
			events.EventDistributedConsentRequestReceived: cl.HandleIncomingCordaEvent,
			events.EventConsentRequestValid:               cl.HandleEventConsentRequestValid,
			events.EventConsentRequestAcked:               cl.HandleEventConsentRequestAcked,
			events.EventConsentDistributed:                cl.HandleEventConsentDistributed,
		})
	if err != nil {
		panic(err)
	}
	return nil
}

// Shutdown is currently a placeholder method. It an be used for unsubscription or other things.
func (ConsentLogic) Shutdown() error {
	// Stub
	return nil
}

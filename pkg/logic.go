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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	core "github.com/nuts-foundation/nuts-go-core"

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
	"github.com/thedevsaddam/gojsonq/v2"
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
	// Create the event to start the consent flow
	event, err := cl.buildConsentRequestConstructedEvent(createConsentRequest)
	if err != nil {
		return nil, err
	}

	// publish the event
	err = cl.EventPublisher.Publish(events.ChannelConsentRequest, *event)
	if err != nil {
		return nil, err
	}
	// extract the events UUID
	eventUUID, err := uuid.FromString(event.UUID)
	if err != nil {
		return nil, err
	}

	logger().Debugf("Published NewConsentRequest to bridge with event: %+v", event)
	return &eventUUID, nil
}

func (cl ConsentLogic) buildConsentRequestConstructedEvent(createConsentRequest *CreateConsentRequest) (*events.Event, error) {
	var err error
	var consentID string
	var records []bridgeClient.ConsentRecord
	legalEntities := []bridgeClient.Identifier{
		bridgeClient.Identifier(createConsentRequest.Actor),
		bridgeClient.Identifier(createConsentRequest.Custodian),
	}

	{
		if !cl.NutsCrypto.KeyExistsFor(cryptoTypes.LegalEntity{URI: string(createConsentRequest.Custodian)}) {
			return nil, errors.New("custodian is not a known vendor")
		}
		logger().Debug("Custodian is known")
	}
	{
		if consentID, err = cl.getConsentID(*createConsentRequest); consentID == "" || err != nil {
			fmt.Println(err)
			// todo: report back the reason why the consentID could not be generated. Probably because the custodian is not managed by this node?
			return nil, errors.New("could not create the consentID for this combination of subject, actor and custodian")
		}
		logger().Debug("ConsentId generated")
	}
	{

	}

	for _, record := range createConsentRequest.Records {
		var fhirConsent string
		var encryptedConsent cryptoTypes.DoubleEncryptedCipherText
		{
			var performer IdentifierURI
			if createConsentRequest.Performer != nil {
				performer = *createConsentRequest.Performer
			}
			if fhirConsent, err = cl.createFhirConsentResource(createConsentRequest.Custodian, createConsentRequest.Actor, createConsentRequest.Subject, performer, record); fhirConsent == "" || err != nil {
				return nil, fmt.Errorf("could not create the FHIR consent resource: %w", err)
			}
			logger().Debug("FHIR resource created", fhirConsent)
		}
		{
			if validationResult, err := cl.validateFhirConsentResource(fhirConsent); !validationResult || err != nil {
				return nil, fmt.Errorf("the generated FHIR consent resource is invalid: %w", err)
			}
			logger().Debug("FHIR resource is valid")
		}
		{
			if encryptedConsent, err = cl.encryptFhirConsent(fhirConsent, *createConsentRequest); err != nil {
				return nil, fmt.Errorf("could not encrypt consent resource for all involved parties: %w", err)
			}
			logger().Debug("FHIR resource encrypted")
		}

		cipherText := base64.StdEncoding.EncodeToString(encryptedConsent.CipherText)
		consentRecordHash := hashFHIRConsent(fhirConsent)

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
			PreviousAttachmentHash: record.PreviousRecordhash,
			ConsentRecordHash:      consentRecordHash,
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
		UUID:                 eventID,
		Name:                 events.EventConsentRequestConstructed,
		InitiatorLegalEntity: string(createConsentRequest.Custodian),
		RetryCount:           0,
		ExternalID:           consentID,
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
		logger().Debugf("All signatures present for UUID: %s", event.ConsentID)
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

					jwkFromSig, err := crypto.MapToJwk(signature.Signature.PublicKey.AdditionalProperties)
					if err != nil {
						errorMsg := fmt.Sprintf("Unable to parse signature public key as JWK: %v", err)
						logger().Warn(errorMsg)
						logger().Debugf("publicKey from signature: %s ", signature.Signature.PublicKey)
						event.Error = &errorMsg
						_ = cl.EventPublisher.Publish(events.ChannelConsentErrored, *event)
						return
					}

					// Check if the organization owns the public key used for signing and whether it was valid at the moment of signing.
					// ========================
					// TODO: Checking it against the current time is wrong; it should be the time of signing.
					// In practice this won't cause problems for now since certificates used for signing consent records
					// are valid for 1 year since they were introduced (april 2020). So we just have to make sure we
					// switch to a signature format (JWS) which does contain the time of signing before april 2021.
					// https://github.com/nuts-foundation/nuts-consent-logic/issues/45
					checkTime := time.Now()
					orgHasKey, err := legalEntity.HasKey(jwkFromSig, checkTime)
					// Fixme: this error handling should be rewritten
					if err != nil {
						errorMsg := fmt.Sprintf("Could not check JWK against organization keys: %v", err)
						logger().Warn(errorMsg)
						event.Error = &errorMsg
						_ = cl.EventPublisher.Publish(events.ChannelConsentErrored, *event)
						return
					}

					if !orgHasKey {
						errorMsg := fmt.Sprintf("Organization %s did not have a valid signature for the corresponding public key at the given time %s", legalEntityID, checkTime.String())
						logger().Warn(errorMsg)
						event.Error = &errorMsg
						_ = cl.EventPublisher.Publish(events.ChannelConsentErrored, *event)
						return
					}

					// checking the actual signature here is not required since it's already checked by the CordApp.
				}
			}

			logger().Debugf("Sending FinalizeRequest to bridge for UUID: %s", event.ConsentID)
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
		if validationResult, err := cl.validateFhirConsentResource(fhirConsent); !validationResult || err != nil {
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

		pubKey, err := cl.NutsCrypto.PublicKeyInJWK(cryptoTypes.LegalEntity{URI: legalEntityToSignFor})
		if err != nil {
			logger().Errorf("Error in getting pubKey for %s: %v", legalEntityToSignFor, err)
			return nil, err
		}

		jwk, err := crypto.JwkToMap(pubKey)
		if err != nil {
			logger().Errorf("Error in transforming pubKey for %s: %v", legalEntityToSignFor, err)
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
				PublicKey: bridgeClient.JWK{AdditionalProperties: jwk},
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
			// if not, check if this node has any keys
			if cl.NutsCrypto.KeyExistsFor(cryptoTypes.LegalEntity{URI: string(ent)}) {
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

// intermediate struct to keep FHIR resource and hash together
type FHIRResourceWithHash struct {
	FHIRResource string
	// Hash represents the attachment hash (zip of cipherText and metadata) from the distributed event model
	Hash string
	// PreviousHash represents the previous attachment hash from the distributed event model (in the case of updates)
	PreviousHash *string
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

	var fhirConsents = map[string]FHIRResourceWithHash{}

	for _, cr := range crs.ConsentRecords {
		for _, organisation := range cr.Metadata.OrganisationSecureKeys {
			if !cl.NutsCrypto.KeyExistsFor(cryptoTypes.LegalEntity{URI: string(organisation.LegalEntity)}) {
				// this organisation is not managed by this node, try with next
				continue
			}

			fhirConsentString, err := cl.decryptConsentRecord(cr, string(organisation.LegalEntity))
			if err != nil {
				logger().Error("Could not decrypt fhir consent")
				return
			}
			fhirConsents[*cr.AttachmentHash] = FHIRResourceWithHash{
				Hash:         *cr.AttachmentHash,
				PreviousHash: cr.Metadata.PreviousAttachmentHash,
				FHIRResource: fhirConsentString,
			}
		}
	}

	patientConsent := cl.PatientConsentFromFHIRRecord(fhirConsents)
	patientConsent.ID = *crs.ConsentId.ExternalId

	if relevant := cl.isRelevantForThisNode(patientConsent); !relevant {
		logger().Error("Got a patientConsent irrelevant for this node")
		return
	}

	logger().Debugf("received patientConsent with %d consentRecords", len(patientConsent.Records))
	logger().Debugf("Storing consent: %+v", patientConsent)

	err = cl.NutsConsentStore.RecordConsent(context.Background(), []cStore.PatientConsent{patientConsent})
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

// hashFHIRConsent generates a consistent hash of the fhirConsent record
func hashFHIRConsent(fhirConsent string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(fhirConsent)))
}

// only consent records of which or the custodian or the actor is managed by this node should be stored
func (cl ConsentLogic) isRelevantForThisNode(patientConsent cStore.PatientConsent) bool {
	// add if custodian is managed by this node
	return cl.NutsCrypto.KeyExistsFor(cryptoTypes.LegalEntity{URI: patientConsent.Custodian}) ||
		cl.NutsCrypto.KeyExistsFor(cryptoTypes.LegalEntity{URI: patientConsent.Actor})
}

// PatientConsentFromFHIRRecord extracts the PatientConsent from a FHIR consent record encoded as json string.
func (ConsentLogic) PatientConsentFromFHIRRecord(fhirConsents map[string]FHIRResourceWithHash) cStore.PatientConsent {
	var patientConsent cStore.PatientConsent

	// FixMe: we should add a check if the actors, subjects and custodians are all the same for each of these fhirConsents
	for _, consent := range fhirConsents {
		fhirConsent := gojsonq.New().JSONString(consent.FHIRResource)
		patientConsent.Actor = string(pkg2.ActorsFrom(fhirConsent)[0])
		patientConsent.Custodian = pkg2.CustodianFrom(fhirConsent)
		patientConsent.Subject = pkg2.SubjectFrom(fhirConsent)
		dataClasses := cStore.DataClassesFromStrings(pkg2.ResourcesFrom(fhirConsent))
		period := pkg2.PeriodFrom(fhirConsent)
		patientConsent.Records = append(patientConsent.Records, cStore.ConsentRecord{DataClasses: dataClasses, ValidFrom: *period[0], ValidTo: period[1], Hash: consent.Hash, PreviousHash: consent.PreviousHash})
	}

	return patientConsent
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
	// This module has no mode feature (server/client) so we delegate it completely to the global mode
	if core.NutsConfig().GetEngineMode("") != core.ServerEngineMode {
		return nil
	}
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

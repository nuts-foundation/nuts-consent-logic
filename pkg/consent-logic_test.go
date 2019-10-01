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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/consent-bridge-go-client/api"
	mock4 "github.com/nuts-foundation/nuts-consent-store/mock"
	pkg3 "github.com/nuts-foundation/nuts-consent-store/pkg"
	mock2 "github.com/nuts-foundation/nuts-crypto/mock"
	pkg2 "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	"github.com/nuts-foundation/nuts-event-octopus/mock"
	"github.com/nuts-foundation/nuts-event-octopus/pkg"
	mock3 "github.com/nuts-foundation/nuts-registry/mock"
	"github.com/nuts-foundation/nuts-registry/pkg/db"
	uuid "github.com/satori/go.uuid"
	"io/ioutil"
	"testing"
	"time"
)

func TestConsentLogic_HandleIncomingCordaEvent(t *testing.T) {

	consentRequestState := api.FullConsentRequestState{}
	encodedState, _ := json.Marshal(consentRequestState)

	t.Run("sending an event without payload should publish an error", func(t *testing.T) {
		// Setup
		ctrl := gomock.NewController(t)
		publisherMock := mock.NewMockIEventPublisher(ctrl)
		// Expect a call to the error channel
		publisherMock.EXPECT().Publish(gomock.Eq(pkg.ChannelConsentErrored), gomock.Any())
		defer ctrl.Finish()

		payload := base64.StdEncoding.EncodeToString([]byte(""))
		event := &(pkg.Event{Name: pkg.EventDistributedConsentRequestReceived, Payload: payload})

		cl := ConsentLogic{EventPublisher: publisherMock}
		cl.HandleIncomingCordaEvent(event)
	})

	t.Run("it finalizes when all attachments are signed and initiatorLegalEntity is set", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		publisherMock := mock.NewMockIEventPublisher(ctrl)
		registryMock := mock3.NewMockRegistryClient(ctrl)
		publicKey := "publicKeyFor00000002"
		registryMock.EXPECT().OrganizationById(gomock.Eq("urn:agb:00000002")).Return(&db.Organization{PublicKey: &publicKey}, nil)

		cypherText := "foo"
		attachmentHash := "123hash"
		signatures := []api.PartyAttachmentSignature{
			{
				Attachment:  "123",
				LegalEntity: "urn:agb:00000002",
				Signature:   api.SignatureWithKey{Data: "signature", PublicKey: "publicKeyFor00000002"},
			},
		}
		consentRequestState.LegalEntities = []api.Identifier{"urn:agb:00000002"}
		consentRequestState.ConsentRecords = []api.ConsentRecord{
			{
				AttachmentHash: &attachmentHash,
				CipherText:     &cypherText,
				Signatures:     &signatures,
			},
		}
		encodedState, _ = json.Marshal(consentRequestState)
		payload := base64.StdEncoding.EncodeToString(encodedState)
		publisherMock.EXPECT().Publish(gomock.Eq(pkg.ChannelConsentRequest), pkg.Event{Name: pkg.EventAllSignaturesPresent, Payload: payload, InitiatorLegalEntity: "urn:agb:00000001"})
		defer ctrl.Finish()

		event := &(pkg.Event{Name: pkg.EventDistributedConsentRequestReceived, Payload: payload, InitiatorLegalEntity: "urn:agb:00000001"})

		cl := ConsentLogic{EventPublisher: publisherMock, NutsRegistry: registryMock}
		cl.HandleIncomingCordaEvent(event)
	})

	t.Run("when no signatures needed and this node is not the initiator it returns without events", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		publisherMock := mock.NewMockIEventPublisher(ctrl)
		defer ctrl.Finish()

		payload := base64.StdEncoding.EncodeToString(encodedState)
		event := &(pkg.Event{Name: pkg.EventDistributedConsentRequestReceived, Payload: payload})

		cl := ConsentLogic{EventPublisher: publisherMock}
		cl.HandleIncomingCordaEvent(event)
	})

	t.Run("no signatures set, but remaining LegalEntity not managed by this node should return", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		publisherMock := mock.NewMockIEventPublisher(ctrl)
		cryptoMock := mock2.NewMockClient(ctrl)

		cryptoMock.EXPECT().PublicKey(types.LegalEntity{URI: "urn:agb:00000001"})
		consentRequestState.LegalEntities = []api.Identifier{"urn:agb:00000001"}
		foo := "foo"
		consentRequestState.ConsentRecords = []api.ConsentRecord{
			{
				CipherText: &foo,
			},
		}
		encodedState, _ := json.Marshal(consentRequestState)
		payload := base64.StdEncoding.EncodeToString(encodedState)

		event := &(pkg.Event{
			Name:    pkg.EventDistributedConsentRequestReceived,
			Payload: payload,
		})

		cl := ConsentLogic{EventPublisher: publisherMock, NutsCrypto: cryptoMock}
		cl.HandleIncomingCordaEvent(event)
	})

	t.Run("not all signatures set, but remaining LegalEntity not managed by this node should return", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		publisherMock := mock.NewMockIEventPublisher(ctrl)
		cryptoMock := mock2.NewMockClient(ctrl)
		cryptoMock.EXPECT().PublicKey(types.LegalEntity{URI: "urn:agb:00000002"})
		defer ctrl.Finish()
		foo := "foo"
		signatures := []api.PartyAttachmentSignature{{Attachment: "foo", LegalEntity: "urn:agb:00000001"}}
		consentRequestState.ConsentRecords = []api.ConsentRecord{
			{
				CipherText: &foo,
				Signatures: &signatures,
			},
		}
		consentRequestState.LegalEntities = []api.Identifier{"urn:agb:00000001", "urn:agb:00000002"}

		encodedState, _ := json.Marshal(consentRequestState)
		payload := base64.StdEncoding.EncodeToString(encodedState)

		event := &(pkg.Event{
			Name:    pkg.EventDistributedConsentRequestReceived,
			Payload: payload,
		})

		cl := ConsentLogic{EventPublisher: publisherMock, NutsCrypto: cryptoMock}
		cl.HandleIncomingCordaEvent(event)
	})

	t.Run("not all signatures set, and remaining LegalEntity managed by this node and valid content should broadcast all checks passed", func(t *testing.T) {
		fooEncoded := base64.StdEncoding.EncodeToString([]byte("foo"))

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		publisherMock := mock.NewMockIEventPublisher(ctrl)
		cryptoMock := mock2.NewMockClient(ctrl)

		cypherText2 := "cyphertext for 00000002"
		// 00000001 already signed
		signatures := []api.PartyAttachmentSignature{{Attachment: "foo", LegalEntity: "urn:agb:00000001"}}
		consentRequestState.ConsentRecords = []api.ConsentRecord{
			{
				CipherText: &fooEncoded,
				Metadata: &api.Metadata{
					OrganisationSecureKeys: []api.ASymmetricKey{{LegalEntity: "urn:agb:00000002", CipherText: &cypherText2}},
				},
				Signatures: &signatures,
			},
		}
		// two parties involved in this transaction
		consentRequestState.LegalEntities = []api.Identifier{"urn:agb:00000001", "urn:agb:00000002"}
		// 00000002 is managed by this node
		cryptoMock.EXPECT().PublicKey(types.LegalEntity{URI: "urn:agb:00000002"}).Return("public key of urn:agb:00000002", nil)

		// expect to receive a decrypt call for 00000002
		validConsent, err := ioutil.ReadFile("../test-data/valid-consent.json")
		if err != nil {
			t.Error(err)
		}
		cryptoMock.EXPECT().DecryptKeyAndCipherTextFor(gomock.Any(), types.LegalEntity{URI: "urn:agb:00000002"}).Return(validConsent, nil)

		encodedState, _ := json.Marshal(consentRequestState)
		payload := base64.StdEncoding.EncodeToString(encodedState)
		event := &(pkg.Event{
			Name:    pkg.EventDistributedConsentRequestReceived,
			Payload: payload,
		})

		expectedEvent := event
		expectedEvent.Name = pkg.EventConsentRequestValid

		// expect to receive a all check passed event
		publisherMock.EXPECT().Publish(gomock.Eq(pkg.ChannelConsentRequest), *expectedEvent)

		cl := ConsentLogic{EventPublisher: publisherMock, NutsCrypto: cryptoMock}
		cl.HandleIncomingCordaEvent(event)
	})

}

func TestConsentLogic_createNewConsentRequestEvent(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	publisherMock := mock.NewMockIEventPublisher(ctrl)

	subjectID := "bsn:999999990"
	custodianID := "agb:00000001"
	party1ID := "agb:00000002"
	performerID := "agb:00000007"

	cryptoClient := pkg2.NewCryptoClient()

	_ = cryptoClient.GenerateKeyPairFor(types.LegalEntity{URI: custodianID})

	reader := rand.Reader
	key, _ := rsa.GenerateKey(reader, 2048)
	pub := key.PublicKey
	pubASN1, _ := x509.MarshalPKIXPublicKey(&pub)
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})
	publicKeyID1 := string(pubBytes)

	registryClient := mock3.NewMockRegistryClient(ctrl)
	registryClient.EXPECT().OrganizationById(gomock.Eq(party1ID)).Return(&db.Organization{PublicKey: &publicKeyID1}, nil)

	cl := ConsentLogic{EventPublisher: publisherMock, NutsCrypto: cryptoClient, NutsRegistry: registryClient}
	performer := IdentifierURI(performerID)
	ccr := &CreateConsentRequest{
		Actor:     IdentifierURI(party1ID),
		Custodian: IdentifierURI(custodianID),
		Performer: &performer,
		Records: []Record{{
			Period:       &Period{Start: time.Now()},
			ConsentProof: nil,
		}},
		Subject: IdentifierURI(subjectID),
	}
	event, err := cl.buildConsentRequestConstructedEvent(ccr)
	if err != nil {
		t.Error("did not expect error:", err)
	}

	crs := api.FullConsentRequestState{}
	decodedPayload, _ := base64.StdEncoding.DecodeString(event.Payload)
	_ = json.Unmarshal(decodedPayload, &crs)

	legalEntityToSignFor := cl.findFirstEntityToSignFor(crs.ConsentRecords[0].Signatures, crs.LegalEntities)
	_, err = cl.decryptConsentRecord(crs.ConsentRecords[0], legalEntityToSignFor)
	if err != nil {
		t.Error("Could not decrypt consent", err)
	}

	// the event contains a valid UUID
	_, err = uuid.FromString(event.Uuid)
	if err != nil {
		t.Error("event does not contain a valid UUID", err)
	}

}

func TestConsentLogic_isRelevantForThisNode(t *testing.T) {
	allRules := []pkg3.PatientConsent{{
		Custodian: "00000001",
		Actor:     "00000002",
	}, {
		Custodian: "00000001",
		Actor:     "00000003",
	}}

	t.Run("current node manges one actor: 00000002", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cryptoMock := mock2.NewMockClient(ctrl)
		cryptoMock.EXPECT().PublicKey(types.LegalEntity{URI: "00000001"}).AnyTimes().Return("", errors.New("could not load key"))
		cryptoMock.EXPECT().PublicKey(types.LegalEntity{URI: "00000002"}).AnyTimes().Return("key of 2", nil)
		cryptoMock.EXPECT().PublicKey(types.LegalEntity{URI: "00000003"}).AnyTimes().Return("", errors.New("could not load key"))

		cl := ConsentLogic{NutsCrypto: cryptoMock}
		if !cl.isRelevantForThisNode(allRules[0]) {
			t.Error("expected rule to be valid")
		}
		if cl.isRelevantForThisNode(allRules[1]) {
			t.Error("expected rule to be invalid")
		}
	})

	t.Run("current node manges both actors", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cryptoMock := mock2.NewMockClient(ctrl)
		cryptoMock.EXPECT().PublicKey(types.LegalEntity{URI: "00000001"}).AnyTimes().Return("", errors.New("could not load key"))
		cryptoMock.EXPECT().PublicKey(types.LegalEntity{URI: "00000002"}).AnyTimes().Return("key of 2", nil)
		cryptoMock.EXPECT().PublicKey(types.LegalEntity{URI: "00000003"}).AnyTimes().Return("key of 3", nil)

		cl := ConsentLogic{NutsCrypto: cryptoMock}
		if !cl.isRelevantForThisNode(allRules[0]) {
			t.Error("expected rule to be valid")
		}
		if !cl.isRelevantForThisNode(allRules[1]) {
			t.Error("expected rule to be valid")
		}
	})
	t.Run("current node manges custodian", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cryptoMock := mock2.NewMockClient(ctrl)
		cryptoMock.EXPECT().PublicKey(types.LegalEntity{URI: "00000001"}).AnyTimes().Return("key of 1", nil)
		cryptoMock.EXPECT().PublicKey(types.LegalEntity{URI: "00000002"}).AnyTimes().Return("key of 2", errors.New("could not load key"))
		cryptoMock.EXPECT().PublicKey(types.LegalEntity{URI: "00000003"}).AnyTimes().Return("key of 3", errors.New("could not load key"))

		cl := ConsentLogic{NutsCrypto: cryptoMock}
		if !cl.isRelevantForThisNode(allRules[0]) {
			t.Error("expected rule to be valid")
		}
		if !cl.isRelevantForThisNode(allRules[1]) {
			t.Error("expected rule to be valid")
		}
	})
}

func TestConsentLogic_SignConsentRequest(t *testing.T) {
	legalEntity := "00000001"
	hexEncodedHash := []byte("attachmenthash123abc")
	consentRecordHash := hex.EncodeToString(hexEncodedHash)

	// setup the mocks
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	cryptoMock := mock2.NewMockClient(ctrl)
	cryptoMock.EXPECT().PublicKey(types.LegalEntity{URI: legalEntity}).AnyTimes().Return("key of 1", nil)
	cryptoMock.EXPECT().SignFor(hexEncodedHash, gomock.Eq(types.LegalEntity{URI: legalEntity})).Return([]byte("signedBytes"), nil)

	// prepare method parameter
	event := pkg.Event{}
	fcrs := api.FullConsentRequestState{
		LegalEntities: []api.Identifier{api.Identifier(legalEntity)},
		ConsentRecords: []api.ConsentRecord{
			{
				AttachmentHash: &consentRecordHash,
			},
		},
	}
	payload, _ := json.Marshal(fcrs)
	event.Payload = base64.StdEncoding.EncodeToString(payload)

	// make the actual request
	cl := ConsentLogic{NutsCrypto: cryptoMock}
	newEvent, err := cl.signConsentRequest(event)

	// check for errors
	if err != nil {
		t.Fatalf("did not expected error: %s", err)
	}
	if newEvent.Error != nil {
		t.Errorf("did not expected error: %s", *newEvent.Error)
	}

	// decode payload
	pas := api.PartyAttachmentSignature{}
	decodedPayload, _ := base64.StdEncoding.DecodeString(newEvent.Payload)
	_ = json.Unmarshal(decodedPayload, &pas)

	// Check all the values
	if string(pas.LegalEntity) != "00000001" {
		t.Error("expected signature")
	}

	if pas.Signature.PublicKey != "key of 1" {
		t.Error("expected payload.signature.publicKey to be set")
	}

	encodedSignatureBytes := base64.StdEncoding.EncodeToString([]byte("signedBytes"))
	if pas.Signature.Data != encodedSignatureBytes {
		t.Errorf("expected payload.signature.Data to be the signature %+v. got %+v", encodedSignatureBytes, pas.Signature.Data)
	}

	if pas.Attachment != consentRecordHash {
		t.Error("expected payload.Attachment to be set")
	}
}

func TestConsentLogic_ConsentRulesFromFHIRRecord(t *testing.T) {
	validConsent, err := ioutil.ReadFile("../test-data/valid-consent.json")
	consentWithHash := FHIRResourceWithHash{FHIRResource:string(validConsent), Hash:"123"}
	if err != nil {
		t.Error(err)
	}

	cl := ConsentLogic{}
	patientConsent := cl.PatientConsentFromFHIRRecord([]FHIRResourceWithHash{consentWithHash})

	expectedCustodian := "urn:oid:2.16.840.1.113883.2.4.6.1:00000000"
	actor := "urn:oid:2.16.840.1.113883.2.4.6.1:00000001"
	subject := "urn:oid:2.16.840.1.113883.2.4.6.3:999999990"

	if patientConsent.Custodian != expectedCustodian {
		t.Errorf("expected custodian with id: %s, got %s instead", expectedCustodian, patientConsent.Custodian)
	}
	if patientConsent.Actor != actor {
		t.Errorf("expected actor with id: %s, got %s instead", actor, patientConsent.Actor)
	}
	if patientConsent.Subject != subject {
		t.Errorf("expected subject with bsn: %s, got %s instead", subject, patientConsent.Subject)
	}
	if len(patientConsent.Records) != 1 {
		t.Errorf("expected 1 record, got %d instedad", len(patientConsent.Records))
	}
	record := patientConsent.Records[0]
	// "start": "2019-01-01T11:00:00Z",
	// "end": "2019-07-01T11:00:00Z"
	if record.ValidFrom.Month() != 1 || record.ValidTo.Month() != 7 {
		t.Errorf("expected validFrom and validTo to have correct values got %v, %v", record.ValidFrom.Month(), record.ValidTo.Month())
	}

}

func TestConsentLogic_HandleEventConsentDistributed(t *testing.T) {
	//t.Skip("the distributed_event is out of date. Collect a new one.")
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	cryptoMock := mock2.NewMockClient(ctrl)
	cryptoMock.EXPECT().PublicKey(types.LegalEntity{URI: "urn:oid:2.16.840.1.113883.2.4.6.1:00000000"}).AnyTimes().Return("key of 0", nil)
	cryptoMock.EXPECT().PublicKey(types.LegalEntity{URI: "urn:oid:2.16.840.1.113883.2.4.6.1:00000001"}).AnyTimes().Return("", nil)

	validConsent, err := ioutil.ReadFile("../test-data/fhir-consent.json")
	if err != nil {
		t.Error(err)
	}
	cryptoMock.EXPECT().DecryptKeyAndCipherTextFor(gomock.Any(), types.LegalEntity{URI: "urn:oid:2.16.840.1.113883.2.4.6.1:00000000"}).Return(validConsent, nil)
	start, _ := time.Parse(time.RFC3339, "2019-07-01T12:00:00+02:00")
	end, _ := time.Parse(time.RFC3339, "2020-07-01T12:00:00+02:00")

	consentStoreMock := mock4.NewMockConsentStoreClient(ctrl)
	patientConsents := []pkg3.PatientConsent{{
		ID:        "35d82f6dce72592cd2e9a197f50506281778e4aba59bcde3bd930bbf95386304",
		Actor:     "urn:oid:2.16.840.1.113883.2.4.6.1:00000001",
		Custodian: "urn:oid:2.16.840.1.113883.2.4.6.1:00000000",
		Records:   []pkg3.ConsentRecord{{Resources: []pkg3.Resource{{ConsentRecordID: 0, ResourceType: "Observation",}}, ValidFrom: start, ValidTo: end, Hash: "71A92248E30B88FCDFC884D777A52C66F4810AB33A30B02A25FF2E17FBDF9857"}},
		Subject:   "urn:oid:2.16.840.1.113883.2.4.6.3:999999990",
	}}
	consentStoreMock.EXPECT().RecordConsent(context.Background(), patientConsents).Return(nil)

	publisherMock := mock.NewMockIEventPublisher(ctrl)
	publisherMock.EXPECT().Publish(gomock.Eq(pkg.ChannelConsentRequest), gomock.Any())

	cl := &ConsentLogic{NutsCrypto: cryptoMock, NutsConsentStore: consentStoreMock, EventPublisher: publisherMock}
	eventConsentDistributed, err := ioutil.ReadFile("../test-data/distributed_event")
	if err != nil {
		t.Error(err)
	}
	event := &pkg.Event{
		Payload: string(eventConsentDistributed),
	}
	cl.HandleEventConsentDistributed(event)
}

func Test_hashFHIRConsent(t *testing.T) {
	// expected value calculated by command `$ echo -n "test" | shasum -a 256`
	expected := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	if got := hashFHIRConsent("test"); got != expected  {
		t.Errorf("expected correct shasum of fhir consent. got: [%s] expected: [%s]", got, expected)
	}
}
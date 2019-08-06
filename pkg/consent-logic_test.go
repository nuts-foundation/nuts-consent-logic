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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/consent-bridge-go-client/api"
	pkg3 "github.com/nuts-foundation/nuts-consent-store/pkg"
	mock2 "github.com/nuts-foundation/nuts-crypto/mock"
	pkg2 "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	"github.com/nuts-foundation/nuts-event-octopus/mock"
	"github.com/nuts-foundation/nuts-event-octopus/pkg"
	mock3 "github.com/nuts-foundation/nuts-registry/mock"
	"github.com/nuts-foundation/nuts-registry/pkg/db"
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
		payload := base64.StdEncoding.EncodeToString(encodedState)
		publisherMock.EXPECT().Publish(gomock.Eq(pkg.ChannelConsentRequest), pkg.Event{Name: pkg.EventAllSignaturesPresent, Payload: payload, InitiatorLegalEntity: "urn:agb:00000001"})
		defer ctrl.Finish()

		event := &(pkg.Event{Name: pkg.EventDistributedConsentRequestReceived, Payload: payload, InitiatorLegalEntity: "urn:agb:00000001"})

		cl := ConsentLogic{EventPublisher: publisherMock}
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
		//consentRequestState.Signatures = []api.PartyAttachmentSignature{{Attachment: "foo", LegalEntity: "urn:agb:00000001"}}
		consentRequestState.LegalEntities = []api.Identifier{"urn:agb:00000001"}
		foo := "foo"
		consentRequestState.CipherText = &foo
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
		consentRequestState.Signatures = []api.PartyAttachmentSignature{{Attachment: "foo", LegalEntity: "urn:agb:00000001"}}
		consentRequestState.LegalEntities = []api.Identifier{"urn:agb:00000001", "urn:agb:00000002"}
		foo := "foo"
		consentRequestState.CipherText = &foo

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
		consentRequestState.CipherText = &fooEncoded

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		publisherMock := mock.NewMockIEventPublisher(ctrl)
		cryptoMock := mock2.NewMockClient(ctrl)

		cypherText2 := "cyphertext for 00000002"
		consentRequestState.Metadata = &api.Metadata{
			OrganisationSecureKeys: []api.ASymmetricKey{{LegalEntity: "urn:agb:00000002", CipherText: &cypherText2}},
		}
		// two parties involved in this transaction
		consentRequestState.LegalEntities = []api.Identifier{"urn:agb:00000001", "urn:agb:00000002"}
		// 00000001 already signed
		consentRequestState.Signatures = []api.PartyAttachmentSignature{{Attachment: "foo", LegalEntity: "urn:agb:00000001"}}
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

func TestConsentLogic_StartConsentFlow(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	publisherMock := mock.NewMockIEventPublisher(ctrl)

	subjectId := "bsn:999999990"
	custodianId := "agb:00000001"
	party1Id := "agb:00000002"
	performerId := "agb:00000007"

	cryptoClient := pkg2.NewCryptoClient()

	_ = cryptoClient.GenerateKeyPairFor(types.LegalEntity{URI: custodianId})

	reader := rand.Reader
	key, _ := rsa.GenerateKey(reader, 2048)
	pub := key.PublicKey
	pubASN1 := x509.MarshalPKCS1PublicKey(&pub)
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})
	publicKeyId1 := string(pubBytes)

	registryClient := mock3.NewMockRegistryClient(ctrl)
	registryClient.EXPECT().OrganizationById(gomock.Eq(party1Id)).Return(&db.Organization{PublicKey: &publicKeyId1}, nil)

	cl := ConsentLogic{EventPublisher: publisherMock, NutsCrypto: cryptoClient, NutsRegistry: registryClient}
	performer := IdentifierURI(performerId)
	ccr := &CreateConsentRequest{
		Actors:       []IdentifierURI{IdentifierURI(party1Id)},
		ConsentProof: nil,
		Custodian:    IdentifierURI(custodianId),
		Performer:    &performer,
		Period:       &Period{Start: time.Now()},
		Subject:      IdentifierURI(subjectId),
	}
	event, err := cl.createNewConsentRequestEvent(ccr)
	if err != nil {
		t.Error("did not expect error:", err)
	}

	crs := api.FullConsentRequestState{}
	decodedPayload, err := base64.StdEncoding.DecodeString(event.Payload)
	_ = json.Unmarshal(decodedPayload, &crs)

	legalEntityToSignFor := cl.findFirstEntityToSignFor(crs.Signatures, crs.LegalEntities)
	_, err = cl.decryptConsentRecord(crs, legalEntityToSignFor)

	if err != nil {
		t.Error("Could not decrypt consent", err)
	}

}

func TestConsentLogic_filterConssentRules(t *testing.T) {
	allRules := []pkg3.ConsentRule{{
		Custodian: "00000001",
		Actor:     "00000002",
	}, {
		Custodian: "00000001",
		Actor:     "00000003",
	}}

	t.Run("current node manges one actor", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cryptoMock := mock2.NewMockClient(ctrl)
		cryptoMock.EXPECT().PublicKey(types.LegalEntity{URI: "00000001"}).AnyTimes().Return("", errors.New("could not load key"))
		cryptoMock.EXPECT().PublicKey(types.LegalEntity{URI: "00000002"}).AnyTimes().Return("key of 2", nil)
		cryptoMock.EXPECT().PublicKey(types.LegalEntity{URI: "00000003"}).AnyTimes().Return("", errors.New("could not load key"))

		cl := ConsentLogic{NutsCrypto: cryptoMock}
		filteredRules := cl.filterConssentRules(allRules)
		if len(filteredRules) != 1 {
			t.Errorf("Expected only one valid rule")
		}
		if filteredRules[0].Actor != "00000002" {
			t.Errorf("expected different actor")
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
		filteredRules := cl.filterConssentRules(allRules)
		if len(filteredRules) != 2 {
			t.Errorf("Expected two valid rules")
		}
		if filteredRules[0].Actor != "00000002" {
			t.Errorf("expected different actor, got: %s", filteredRules[0].Actor)
		}
		if filteredRules[1].Actor != "00000003" {
			t.Errorf("expected different actor, got: %s", filteredRules[1].Actor)
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
		filteredRules := cl.filterConssentRules(allRules)
		if len(filteredRules) != 2 {
			t.Errorf("Expected two valid rules")
		}
		if filteredRules[0].Actor != "00000002" {
			t.Errorf("expected different actor, got: %s", filteredRules[0].Actor)
		}
		if filteredRules[1].Actor != "00000003" {
			t.Errorf("expected different actor, got: %s", filteredRules[1].Actor)
		}
	})
}

func TestConsentLogic_ConsentRulesFromFHIRRecord(t *testing.T) {
	validConsent, err := ioutil.ReadFile("../test-data/valid-consent.json")
	if err != nil {
		t.Error(err)
	}

	cl := ConsentLogic{}
	consentRules := cl.ConsentRulesFromFHIRRecord(string(validConsent))

	if len(consentRules) != 2 {
		t.Errorf("Expected 2 rules, got %d instead", len(consentRules))
	}

	expectedCustodian := "urn:oid:2.16.840.1.113883.2.4.6.3:00000000"
	firstActor := "urn:oid:2.16.840.1.113883.2.4.6.3:00000001"
	secondActor := "urn:oid:2.16.840.1.113883.2.4.6.3:00000002"
	subject := "urn:oid:2.16.840.1.113883.2.4.6.1:999999990"

	rule := consentRules[0]
	if rule.Custodian != expectedCustodian {
		t.Errorf("expected custodian with id: %s, got %s instead", expectedCustodian, rule.Custodian)
	}
	if rule.Actor != firstActor {
		t.Errorf("expected actor with id: %s, got %s instead", firstActor, rule.Actor)
	}
	if rule.Subject != subject {
		t.Errorf("expected subject with bsn: %s, got %s instead", subject, rule.Subject)

	}

	// check the second rule
	rule = consentRules[1]
	if rule.Custodian != expectedCustodian {
		t.Errorf("expected custodian with id: %s, got %s instead", expectedCustodian, rule.Custodian)
	}
	if rule.Actor != secondActor {
		t.Errorf("expected actor with id: %s, got %s instead", secondActor, rule.Actor)
	}
	if rule.Subject != subject {
		t.Errorf("expected subject with bsn: %s, got %s instead", subject, rule.Subject)

	}
}

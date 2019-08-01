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
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/consent-bridge-go-client/api"
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

		event := &(pkg.Event{Name: pkg.EventDistributedConsentRequestReceived, Payload: string(payload), InitiatorLegalEntity: "urn:agb:00000001"})

		cl := ConsentLogic{EventPublisher: publisherMock}
		cl.HandleIncomingCordaEvent(event)
	})

	t.Run("when no signatures needed and this node is not the initiator it returns without events", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		publisherMock := mock.NewMockIEventPublisher(ctrl)
		defer ctrl.Finish()

		payload := base64.StdEncoding.EncodeToString(encodedState)
		event := &(pkg.Event{Name: pkg.EventDistributedConsentRequestReceived, Payload: string(payload)})

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
			Payload: string(payload),
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

	cryptoClient.GenerateKeyPairFor(types.LegalEntity{URI: custodianId})
	//publicKeyCustodian, _ := cryptoClient.PublicKey(types.LegalEntity{URI: custodianId})

	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, 2048)
	pub := key.PublicKey
	pubASN1 := x509.MarshalPKCS1PublicKey(&pub)
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})
	publicKeyId1 := string(pubBytes)

	//publisherMock.EXPECT().Publish(gomock.Eq(pkg.ChannelConsentRequest), gomock.Any())
	registryClient := mock3.NewMockRegistryClient(ctrl)
	//registryClient.EXPECT().OrganizationById(gomock.Eq(custodianId)).Return(&db.Organization{PublicKey: &publicKeyCustodian}, nil)
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
	json.Unmarshal(decodedPayload, &crs)

	encodedCipherText := crs.CipherText
	cipherText, err := base64.StdEncoding.DecodeString(*encodedCipherText)
	legalEntityToSignFor := cl.findFirstEntityToSignFor(crs.Signatures, crs.LegalEntities)
	_, err = cl.decryptConsentRecord(cipherText, crs, legalEntityToSignFor)

	if err != nil {
		t.Error("Could not decrypt consent", err)
	}

}
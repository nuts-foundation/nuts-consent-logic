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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-consent-logic/test"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-go-test/io"

	"github.com/golang/mock/gomock"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/consent-bridge-go-client/api"
	mock4 "github.com/nuts-foundation/nuts-consent-store/mock"
	pkg3 "github.com/nuts-foundation/nuts-consent-store/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/cert"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	mock2 "github.com/nuts-foundation/nuts-crypto/test/mock"
	"github.com/nuts-foundation/nuts-event-octopus/mock"
	"github.com/nuts-foundation/nuts-event-octopus/pkg"
	core "github.com/nuts-foundation/nuts-go-core"
	mock3 "github.com/nuts-foundation/nuts-registry/mock"
	"github.com/nuts-foundation/nuts-registry/pkg/db"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

func TestConsentLogic_HandleIncomingCordaEvent(t *testing.T) {

	consentRequestState := api.FullConsentRequestState{}
	encodedState, _ := json.Marshal(consentRequestState)

	t.Run("sending an event without payload should publish an error", func(t *testing.T) {
		// Setup
		ctrl := gomock.NewController(t)
		publisherMock := mock.NewMockIEventPublisher(ctrl)
		// Expect a call to the error channel
		publisherMock.EXPECT().Publish(gomock.Eq(pkg.ChannelConsentRequest), gomock.Any())
		defer ctrl.Finish()

		payload := base64.StdEncoding.EncodeToString([]byte(""))
		event := &(pkg.Event{Name: pkg.EventDistributedConsentRequestReceived, Payload: payload})

		cl := ConsentLogic{EventPublisher: publisherMock}
		cl.HandleIncomingCordaEvent(event)
	})

	t.Run("testing public keys", func(t *testing.T) {
		validPublicKey := `{
    "kty": "RSA",
    "n": "uKjoosQFSAYCS-QQGVBh8N-GFd34ufUAdGBwLvvMzB0JPpGpEX0oo8RS4dL8JCruHlzT4HP_bPzIF41fc4WTiOFPFpktY1tJdBS2_XS8i2ehzFLw3YJ3qWX9XQGdJfNHdbbz9h1RXIgBs7UdipHD0-hW-XesT_YkhJSrOA5UxglojI2LrArCzbwlbUUhidMH7962uC87IYvhOux8DK54aOEteNER-ZkZRpnR5vBYT03Soje8KBNez2x-GUlhRDQwS_11PDditMGObAScaJVHrZm-HohiH_rRcQFl0QWLWCFwpPdfu5eHEputNl9GOjvPpRezuvDYN641jL7uZ_rokQ",
    "e": "AQAB"
}`

		validJwk := &api.JWK{}
		json.Unmarshal([]byte(validPublicKey), validJwk)

		signatures := []api.PartyAttachmentSignature{
			{
				LegalEntity: "urn:oid:2.16.840.1.113883.2.4.6.1:00000002",
				Signature:   api.SignatureWithKey{Data: "signature", PublicKey: *validJwk},
			},
		}
		consentRequestState.LegalEntities = []api.Identifier{"urn:oid:2.16.840.1.113883.2.4.6.1:00000002"}
		consentRequestState.ConsentRecords = []api.ConsentRecord{
			{
				Signatures: &signatures,
			},
		}

		t.Run("it succeeds when organization has multiple keys", func(t *testing.T) {
			otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)

			ctrl := gomock.NewController(t)
			publisherMock := mock.NewMockIEventPublisher(ctrl)
			registryMock := mock3.NewMockRegistryClient(ctrl)
			registryMock.EXPECT().OrganizationById(gomock.Eq(test.AGBPartyID("00000002"))).Return(getOrganization(&otherKey.PublicKey, validPublicKey), nil)

			encodedState, _ = json.Marshal(consentRequestState)
			payload := base64.StdEncoding.EncodeToString(encodedState)
			event := &(pkg.Event{Name: pkg.EventDistributedConsentRequestReceived, Payload: payload, InitiatorLegalEntity: "urn:oid:2.16.840.1.113883.2.4.6.1:00000001"})
			publisherMock.EXPECT().Publish(gomock.Eq(pkg.ChannelConsentRequest), gomock.Any())

			cl := ConsentLogic{EventPublisher: publisherMock, NutsRegistry: registryMock}
			cl.HandleIncomingCordaEvent(event)
		})

		t.Run("it fails with an invalid registry key", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			publisherMock := mock.NewMockIEventPublisher(ctrl)
			registryMock := mock3.NewMockRegistryClient(ctrl)
			registryMock.EXPECT().OrganizationById(gomock.Eq(test.AGBPartyID("00000002"))).Return(&db.Organization{Keys: []interface{}{map[string]interface{}{}}}, nil)

			encodedState, _ = json.Marshal(consentRequestState)
			payload := base64.StdEncoding.EncodeToString(encodedState)
			event := &(pkg.Event{Name: pkg.EventDistributedConsentRequestReceived, Payload: payload, InitiatorLegalEntity: "urn:oid:2.16.840.1.113883.2.4.6.1:00000001"})
			publisherMock.EXPECT().Publish(gomock.Eq(pkg.ChannelConsentRequest), gomock.Any())

			cl := ConsentLogic{EventPublisher: publisherMock, NutsRegistry: registryMock}
			cl.HandleIncomingCordaEvent(event)
		})

		t.Run("it fails with an invalid signature key", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			publisherMock := mock.NewMockIEventPublisher(ctrl)
			registryMock := mock3.NewMockRegistryClient(ctrl)
			registryMock.EXPECT().OrganizationById(gomock.Eq(test.AGBPartyID("00000002"))).Return(getOrganization(validPublicKey), nil)
			signatures[0].Signature = api.SignatureWithKey{Data: "signature", PublicKey: api.JWK{}}

			encodedState, _ = json.Marshal(consentRequestState)
			payload := base64.StdEncoding.EncodeToString(encodedState)
			event := &(pkg.Event{Name: pkg.EventDistributedConsentRequestReceived, Payload: payload, InitiatorLegalEntity: "urn:oid:2.16.840.1.113883.2.4.6.1:00000001"})
			publisherMock.EXPECT().Publish(gomock.Eq(pkg.ChannelConsentRequest), gomock.Any())

			cl := ConsentLogic{EventPublisher: publisherMock, NutsRegistry: registryMock}
			cl.HandleIncomingCordaEvent(event)
		})

		t.Run("it fails when the keys are not equal", func(t *testing.T) {

			otherValidPublicKey := `{
    "kty": "RSA",
    "n": "uKjoosQFSAYCS-QQGVBh8N-GFd34ufUAdGBwLvvMzB0JPpGpEX0oo8RS4dL8JCruHlzT4HP_bPzIF41fc4WTiOFPFpktY1tJdBS2_XS8i2ehzFLw3YJ3qWX9XQGdJfNHdbbz9h1RXIgBs7UdipHD0-hW-XesT_YkhJSrOA5UxglojI2LgArCzbwlbUUhidMH7962uC87IYvhOux8DK54aOEteNER-ZkZRpnR5vBYT03Soje8KBNez2x-GUlhRDQwS_11PDditMGObAScaJVHrZm-HohiH_rRcQFl0QWLWCFwpPdfu5eHEputNl9GOjvPpRezuvDYN641jL7uZ_rokQ",
    "e": "AQAB"
}`
			otherValidJwk := &api.JWK{}
			json.Unmarshal([]byte(otherValidPublicKey), otherValidJwk)
			ctrl := gomock.NewController(t)
			publisherMock := mock.NewMockIEventPublisher(ctrl)
			registryMock := mock3.NewMockRegistryClient(ctrl)
			registryMock.EXPECT().OrganizationById(gomock.Eq(test.AGBPartyID("00000002"))).Return(getOrganization(validPublicKey), nil)
			signatures[0].Signature = api.SignatureWithKey{Data: "signature", PublicKey: *otherValidJwk}

			encodedState, _ = json.Marshal(consentRequestState)
			payload := base64.StdEncoding.EncodeToString(encodedState)
			event := &(pkg.Event{Name: pkg.EventDistributedConsentRequestReceived, Payload: payload, InitiatorLegalEntity: "urn:oid:2.16.840.1.113883.2.4.6.1:00000001"})
			publisherMock.EXPECT().Publish(gomock.Eq(pkg.ChannelConsentRequest), gomock.Any())

			cl := ConsentLogic{EventPublisher: publisherMock, NutsRegistry: registryMock}
			cl.HandleIncomingCordaEvent(event)
		})
	})

	t.Run("it finalizes when all attachments are signed and initiatorLegalEntity is set", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		publisherMock := mock.NewMockIEventPublisher(ctrl)
		registryMock := mock3.NewMockRegistryClient(ctrl)
		publicKey1 := `{
    "kty": "RSA",
    "n": "uKjoosQFSAYCS-QQGVBh8N-GFd34ufUAdGBwLvvMzB0JPpGpEX0oo8RS4dL8JCruHlzT4HP_bPzIF41fc4WTiOFPFpktY1tJdBS2_XS8i2ehzFLw3YJ3qWX9XQGdJfNHdbbz9h1RXIgBs7UdipHD0-hW-XesT_YkhJSrOA5UxglojI2LrArCzbwlbUUhidMH7962uC87IYvhOux8DK54aOEteNER-ZkZRpnR5vBYT03Soje8KBNez2x-GUlhRDQwS_11PDditMGObAScaJVHrZm-HohiH_rRcQFl0QWLWCFwpPdfu5eHEputNl9GOjvPpRezuvDYN641jL7uZ_rokQ",
    "e": "AQAB"
}`

		jwk := api.JWK{}
		json.Unmarshal([]byte(publicKey1), &jwk)
		registryMock.EXPECT().OrganizationById(gomock.Eq(test.AGBPartyID("00000002"))).Return(getOrganization(jwk.AdditionalProperties), nil)

		cypherText := "foo"
		attachmentHash := "123hash"
		signatures := []api.PartyAttachmentSignature{
			{
				Attachment:  "123",
				LegalEntity: "urn:oid:2.16.840.1.113883.2.4.6.1:00000002",
				Signature:   api.SignatureWithKey{Data: "signature", PublicKey: jwk},
			},
		}
		consentRequestState.LegalEntities = []api.Identifier{"urn:oid:2.16.840.1.113883.2.4.6.1:00000002"}
		consentRequestState.ConsentRecords = []api.ConsentRecord{
			{
				AttachmentHash: &attachmentHash,
				CipherText:     &cypherText,
				Signatures:     &signatures,
			},
		}
		encodedState, _ = json.Marshal(consentRequestState)
		payload := base64.StdEncoding.EncodeToString(encodedState)
		publisherMock.EXPECT().Publish(gomock.Eq(pkg.ChannelConsentRequest), pkg.Event{Name: pkg.EventAllSignaturesPresent, Payload: payload, InitiatorLegalEntity: "urn:oid:2.16.840.1.113883.2.4.6.1:00000001"})
		defer ctrl.Finish()

		event := &(pkg.Event{Name: pkg.EventDistributedConsentRequestReceived, Payload: payload, InitiatorLegalEntity: "urn:oid:2.16.840.1.113883.2.4.6.1:00000001"})

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

		cryptoMock.EXPECT().PrivateKeyExists(types.KeyForEntity(types.LegalEntity{URI: "urn:oid:2.16.840.1.113883.2.4.6.1:00000001"}))
		consentRequestState.LegalEntities = []api.Identifier{"urn:oid:2.16.840.1.113883.2.4.6.1:00000001"}
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
		cryptoMock.EXPECT().PrivateKeyExists(types.KeyForEntity(types.LegalEntity{URI: "urn:oid:2.16.840.1.113883.2.4.6.1:00000002"}))
		defer ctrl.Finish()
		foo := "foo"
		signatures := []api.PartyAttachmentSignature{{Attachment: "foo", LegalEntity: "urn:oid:2.16.840.1.113883.2.4.6.1:00000001"}}
		consentRequestState.ConsentRecords = []api.ConsentRecord{
			{
				CipherText: &foo,
				Signatures: &signatures,
			},
		}
		consentRequestState.LegalEntities = []api.Identifier{"urn:oid:2.16.840.1.113883.2.4.6.1:00000001", "urn:oid:2.16.840.1.113883.2.4.6.1:00000002"}

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
		signatures := []api.PartyAttachmentSignature{{Attachment: "foo", LegalEntity: "urn:oid:2.16.840.1.113883.2.4.6.1:00000001"}}
		consentRequestState.ConsentRecords = []api.ConsentRecord{
			{
				CipherText: &fooEncoded,
				Metadata: &api.Metadata{
					OrganisationSecureKeys: []api.ASymmetricKey{{LegalEntity: "urn:oid:2.16.840.1.113883.2.4.6.1:00000002", CipherText: &cypherText2}},
				},
				Signatures: &signatures,
			},
		}
		// two parties involved in this transaction
		consentRequestState.LegalEntities = []api.Identifier{"urn:oid:2.16.840.1.113883.2.4.6.1:00000001", "urn:oid:2.16.840.1.113883.2.4.6.1:00000002"}
		// 00000002 is managed by this node
		cryptoMock.EXPECT().PrivateKeyExists(types.KeyForEntity(types.LegalEntity{URI: "urn:oid:2.16.840.1.113883.2.4.6.1:00000002"})).Return(true)

		// expect to receive a decrypt call for 00000002
		validConsent, err := ioutil.ReadFile("../test-data/valid-consent.json")
		if err != nil {
			t.Error(err)
		}
		cryptoMock.EXPECT().DecryptKeyAndCipherText(gomock.Any(), types.KeyForEntity(types.LegalEntity{URI: "urn:oid:2.16.840.1.113883.2.4.6.1:00000002"})).Return(validConsent, nil)

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
	cryptoClient := createCrypto(io.TestDirectory(t))
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	publisherMock := mock.NewMockIEventPublisher(ctrl)

	subjectID := test.BSNPartyID("999999990")
	custodianID := test.AGBPartyID("00000001")
	party1ID := test.AGBPartyID("00000002")
	performerID := test.AGBPartyID("00000007")

	_, _ = cryptoClient.GenerateKeyPair(types.KeyForEntity(types.LegalEntity{URI: custodianID.String()}), false)

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
	registryClient.EXPECT().OrganizationById(gomock.Eq(party1ID)).Return(getOrganization(publicKeyID1), nil)

	cl := ConsentLogic{EventPublisher: publisherMock, NutsCrypto: cryptoClient, NutsRegistry: registryClient}
	performer := performerID
	ccr := &CreateConsentRequest{
		Actor:     party1ID,
		Custodian: custodianID,
		Performer: performer,
		Records: []Record{{
			Period:       Period{Start: time.Now()},
			ConsentProof: nil,
		}},
		Subject: subjectID,
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
	_, err = uuid.FromString(event.UUID)
	if err != nil {
		t.Error("event does not contain a valid UUID", err)
	}

	assert.NotNil(t, crs.CreatedAt)
	assert.NotNil(t, crs.UpdatedAt)
	assert.Equal(t, custodianID.String(), string(crs.InitiatingLegalEntity))
	assert.Equal(t, core.NutsConfig().VendorID().String(), *crs.InitiatingNode)
}

func createCrypto(testDirectory string) *crypto.Crypto {
	cfg := crypto.TestCryptoConfig(testDirectory)
	cfg.Keysize = crypto.MinKeySize
	c := crypto.NewCryptoInstance(cfg)
	if err := c.Configure(); err != nil {
		panic(err)
	}
	return c
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
		cryptoMock.EXPECT().PrivateKeyExists(types.KeyForEntity(types.LegalEntity{URI: "00000001"})).AnyTimes().Return(false)
		cryptoMock.EXPECT().PrivateKeyExists(types.KeyForEntity(types.LegalEntity{URI: "00000002"})).AnyTimes().Return(true)
		cryptoMock.EXPECT().PrivateKeyExists(types.KeyForEntity(types.LegalEntity{URI: "00000003"})).AnyTimes().Return(false)

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
		cryptoMock.EXPECT().PrivateKeyExists(types.KeyForEntity(types.LegalEntity{URI: "00000001"})).AnyTimes().Return(false)
		cryptoMock.EXPECT().PrivateKeyExists(types.KeyForEntity(types.LegalEntity{URI: "00000002"})).AnyTimes().Return(true)
		cryptoMock.EXPECT().PrivateKeyExists(types.KeyForEntity(types.LegalEntity{URI: "00000003"})).AnyTimes().Return(true)

		cl := ConsentLogic{NutsCrypto: cryptoMock}
		if !cl.isRelevantForThisNode(allRules[0]) {
			t.Error("expected rule to be valid")
		}
		if !cl.isRelevantForThisNode(allRules[1]) {
			t.Error("expected rule to be valid")
		}
	})
	t.Run("current node manages custodian", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cryptoMock := mock2.NewMockClient(ctrl)
		cryptoMock.EXPECT().PrivateKeyExists(types.KeyForEntity(types.LegalEntity{URI: "00000001"})).AnyTimes().Return(true)
		cryptoMock.EXPECT().PrivateKeyExists(types.KeyForEntity(types.LegalEntity{URI: "00000002"})).AnyTimes().Return(false)
		cryptoMock.EXPECT().PrivateKeyExists(types.KeyForEntity(types.LegalEntity{URI: "00000003"})).AnyTimes().Return(false)

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
	legalEntity := test.AGBPartyID("00000001")
	hexEncodedHash := []byte("attachmenthash123abc")
	consentRecordHash := hex.EncodeToString(hexEncodedHash)

	// setup the mocks
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	cryptoMock := mock2.NewMockClient(ctrl)
	privkey, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk, _ := jwk.New(&privkey.PublicKey)
	cryptoMock.EXPECT().PrivateKeyExists(types.KeyForEntity(types.LegalEntity{URI: legalEntity.String()})).AnyTimes().Return(true)
	cryptoMock.EXPECT().GetPublicKeyAsJWK(types.KeyForEntity(types.LegalEntity{URI: legalEntity.String()})).AnyTimes().Return(jwk, nil)
	cryptoMock.EXPECT().Sign(hexEncodedHash, gomock.Eq(types.KeyForEntity(types.LegalEntity{URI: legalEntity.String()}))).Return([]byte("signedBytes"), nil)

	// prepare method parameter
	event := pkg.Event{}
	fcrs := api.FullConsentRequestState{
		LegalEntities: []api.Identifier{api.Identifier(legalEntity.String())},
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
	if string(pas.LegalEntity) != legalEntity.String() {
		t.Error("expected signature")
	}

	if len(pas.Signature.PublicKey.AdditionalProperties) == 0 {
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
	prev := "122"
	consentWithHash := FHIRResourceWithHash{FHIRResource: string(validConsent), Hash: "123", PreviousHash: &prev}
	if err != nil {
		t.Error(err)
	}

	cl := ConsentLogic{}
	patientConsent := cl.PatientConsentFromFHIRRecord(map[string]FHIRResourceWithHash{"123": consentWithHash})

	expectedCustodian := "urn:oid:2.16.840.1.113883.2.4.6.1:00000000"
	actor := "urn:oid:2.16.840.1.113883.2.4.6.1:00000001"
	subject := "urn:oid:2.16.840.1.113883.2.4.6.3:999999990"

	assert.Equal(t, expectedCustodian, patientConsent.Custodian)
	assert.Equal(t, actor, patientConsent.Actor)
	assert.Equal(t, subject, patientConsent.Subject)
	assert.Len(t, patientConsent.Records, 1)

	record := patientConsent.Records[0]
	assert.Equal(t, prev, *record.PreviousHash)
	// "start": "2019-01-01T11:00:00Z",
	// "end": "2019-07-01T11:00:00Z"
	if record.ValidFrom.Month() != 1 || record.ValidTo.Month() != 7 {
		t.Errorf("expected validFrom and validTo to have correct values got %v, %v", record.ValidFrom.Month(), record.ValidTo.Month())
	}

}

func TestConsentLogic_HandleEventConsentDistributed(t *testing.T) {
	start, _ := time.Parse(time.RFC3339, "2019-07-01T12:00:00+02:00")
	end, _ := time.Parse(time.RFC3339, "2020-07-01T12:00:00+02:00")
	validConsent, err := ioutil.ReadFile("../test-data/fhir-consent.json")
	if err != nil {
		t.Error(err)
	}
	patientConsents := []pkg3.PatientConsent{{
		ID:        "35d82f6dce72592cd2e9a197f50506281778e4aba59bcde3bd930bbf95386304",
		Actor:     "urn:oid:2.16.840.1.113883.2.4.6.1:00000001",
		Custodian: "urn:oid:2.16.840.1.113883.2.4.6.1:00000000",
		Records:   []pkg3.ConsentRecord{{DataClasses: []pkg3.DataClass{{ConsentRecordID: 0, Code: "http://hl7.org/fhir/resource-types#Observation"}}, ValidFrom: start, ValidTo: &end, Hash: "71A92248E30B88FCDFC884D777A52C66F4810AB33A30B02A25FF2E17FBDF9857"}},
		Subject:   "urn:oid:2.16.840.1.113883.2.4.6.3:999999990",
	}}

	allOrgs := []string{
		"urn:oid:2.16.840.1.113883.2.4.6.1:00000000",
		"urn:oid:2.16.840.1.113883.2.4.6.1:00000001",
	}

	administratedOrgs := [][]string{
		{
			"urn:oid:2.16.840.1.113883.2.4.6.1:00000000",
		},
		{
			"urn:oid:2.16.840.1.113883.2.4.6.1:00000000",
			"urn:oid:2.16.840.1.113883.2.4.6.1:00000001",
		},
	}

	for _, orgs := range administratedOrgs {
		tName := fmt.Sprintf("%v are administrated by one node", orgs)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		publisherMock := mock.NewMockIEventPublisher(ctrl)
		consentStoreMock := mock4.NewMockConsentStoreClient(ctrl)

		eventConsentDistributed, err := ioutil.ReadFile("../test-data/distributed_event")
		if err != nil {
			t.Error(err)
		}
		event := &pkg.Event{
			Payload: string(eventConsentDistributed),
		}

		publisherMock.EXPECT().Publish(gomock.Eq(pkg.ChannelConsentRequest), gomock.Any())
		consentStoreMock.EXPECT().RecordConsent(context.Background(), patientConsents).Return(nil)
		cryptoMock := mock2.NewMockClient(ctrl)
		cl := &ConsentLogic{NutsCrypto: cryptoMock, NutsConsentStore: consentStoreMock, EventPublisher: publisherMock}

		for _, org := range allOrgs {
			cryptoMock.EXPECT().GetPublicKeyAsJWK(types.KeyForEntity(types.LegalEntity{URI: org})).AnyTimes().Return(&jwk.RSAPublicKey{}, nil)
		}

		t.Run(tName, func(t *testing.T) {
			for _, org := range orgs {
				cryptoMock.EXPECT().PrivateKeyExists(types.KeyForEntity(types.LegalEntity{URI: org})).AnyTimes().Return(true)
				cryptoMock.EXPECT().DecryptKeyAndCipherText(gomock.Any(), types.KeyForEntity(types.LegalEntity{URI: org})).AnyTimes().Return(validConsent, nil)
			}
			for _, org := range allOrgs {
				// already set mocks are not overriden
				cryptoMock.EXPECT().PrivateKeyExists(types.KeyForEntity(types.LegalEntity{URI: org})).AnyTimes().Return(false)
			}

			cl.HandleEventConsentDistributed(event)
		})
	}
}

func Test_hashFHIRConsent(t *testing.T) {
	// expected value calculated by command `$ echo -n "test" | shasum -a 256`
	expected := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	if got := hashFHIRConsent("test"); got != expected {
		t.Errorf("expected correct shasum of fhir consent. got: [%s] expected: [%s]", got, expected)
	}
}

func TestConsentLogic_buildConsentRequestConstructedEvent(t *testing.T) {
	validPublicKey := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuKjoosQFSAYCS+QQGVBh
8N+GFd34ufUAdGBwLvvMzB0JPpGpEX0oo8RS4dL8JCruHlzT4HP/bPzIF41fc4WT
iOFPFpktY1tJdBS2/XS8i2ehzFLw3YJ3qWX9XQGdJfNHdbbz9h1RXIgBs7UdipHD
0+hW+XesT/YkhJSrOA5UxglojI2LrArCzbwlbUUhidMH7962uC87IYvhOux8DK54
aOEteNER+ZkZRpnR5vBYT03Soje8KBNez2x+GUlhRDQwS/11PDditMGObAScaJVH
rZm+HohiH/rRcQFl0QWLWCFwpPdfu5eHEputNl9GOjvPpRezuvDYN641jL7uZ/ro
kQIDAQAB
-----END PUBLIC KEY-----`

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	cryptoMock := mock2.NewMockClient(ctrl)
	registryMock := mock3.NewMockRegistryClient(ctrl)
	custodian := test.AGBPartyID("00000001")
	actor := test.AGBPartyID("00000002")
	subject := test.BSNPartyID("1234")

	cryptoMock.EXPECT().GetPublicKeyAsJWK(types.KeyForEntity(types.LegalEntity{URI: custodian.String()})).AnyTimes().Return(&jwk.RSAPublicKey{}, nil)
	cryptoMock.EXPECT().PrivateKeyExists(types.KeyForEntity(types.LegalEntity{URI: custodian.String()})).AnyTimes().Return(true)
	cryptoMock.EXPECT().CalculateExternalId(gomock.Any(), gomock.Any(), gomock.Any()).Return([]byte("externalID"), nil)
	cryptoMock.EXPECT().EncryptKeyAndPlainText(gomock.Any(), gomock.Any()).Return(types.DoubleEncryptedCipherText{}, nil)
	registryMock.EXPECT().OrganizationById(gomock.Eq(actor)).Return(getOrganization(validPublicKey), nil)

	createConsentRequest := &CreateConsentRequest{
		Custodian: custodian,
		Subject:   subject,
		Actor:     actor,
		Records:   []Record{{}},
	}
	consentLogic := &ConsentLogic{NutsRegistry: registryMock, NutsCrypto: cryptoMock}
	event, err := consentLogic.buildConsentRequestConstructedEvent(createConsentRequest)
	assert.Nil(t, err)
	assert.NotNil(t, event, "event should not be nil")
}

// getOrganization helper func to create organization with the given (mixed-format) keys. The keys can be in the following formats:
// - PEM encoded public key as string
// - JSON encoded JWK as string
// - JWK as Go map[string]interface{}
// - RSA public key as Go *rsa.PublicKey
func getOrganization(keys ...interface{}) *db.Organization {
	o := db.Organization{}
	for _, key := range keys {
		var keyAsJWK jwk.Key
		var err error
		{
			keyAsString, ok := key.(string)
			if ok {
				keyAsJWK, _ = cert.PemToJwk([]byte(keyAsString))
				if keyAsJWK == nil {
					var asMap map[string]interface{}
					err := json.Unmarshal([]byte(keyAsString), &asMap)
					if err == nil {
						key = asMap
					}
				}
			}
		}
		{
			keyAsMap2, ok := key.(map[string]interface{})
			if ok {
				keyAsJWK, err = cert.MapToJwk(keyAsMap2)
				if err != nil {
					panic(err)
				}
			}
		}
		{
			keyAsPubKey, ok := key.(*rsa.PublicKey)
			if ok {
				keyAsJWK, _ = jwk.New(keyAsPubKey)
			}
		}
		keyAsMap, _ := cert.JwkToMap(keyAsJWK)
		keyAsMap["kty"] = keyAsJWK.KeyType().String()
		o.Keys = append(o.Keys, keyAsMap)
	}
	return &o
}

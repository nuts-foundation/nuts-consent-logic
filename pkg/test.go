package pkg

import (
	consentStore "github.com/nuts-foundation/nuts-consent-store/pkg"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	eventOctopus "github.com/nuts-foundation/nuts-event-octopus/pkg"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
)

func NewTestConsentLogicInstance(testDirectory string) *ConsentLogic {
	newInstance := NewConsentLogicInstance(ConsentLogicConfig{}, crypto.NewTestCryptoInstance(testDirectory), registry.NewTestRegistryInstance(testDirectory), consentStore.ConsentStoreInstance(), eventOctopus.EventOctopusInstance())
	instance = newInstance
	return newInstance
}

package test

import core "github.com/nuts-foundation/nuts-go-core"

func AGBPartyID(value string) core.PartyID {
	id, _ := core.NewPartyID("2.16.840.1.113883.2.4.6.1", value)
	return id
}

func BSNPartyID(value string) core.PartyID {
	id, _ := core.NewPartyID("2.16.840.1.113883.2.4.6.3", value)
	return id
}

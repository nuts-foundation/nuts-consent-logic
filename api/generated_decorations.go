package api

import (
	core "github.com/nuts-foundation/nuts-go-core"
	"log"
)

func (i *IdentifierURI) UnmarshalJSON(bytes []byte) error {
	partyID := core.PartyID{}
	if err := partyID.UnmarshalJSON(bytes); err != nil {
		return err
	}
	*i = IdentifierURI(partyID.String())
	return nil
}

func (i IdentifierURI) PartyID() core.PartyID {
	id, err := core.ParsePartyID(string(i))
	if err != nil {
		log.Fatalf("should never happen: invalid PartyID: %s", i)
	}
	return id
}

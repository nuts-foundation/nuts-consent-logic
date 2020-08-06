package api

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIdentifierURI(t *testing.T) {
	expected := "urn:oid:1.2.3.4:foobar"
	t.Run("To PartyID", func(t *testing.T) {
		assert.Equal(t, expected, IdentifierURI(expected).PartyID().String())
	})
	t.Run("JSON unmarshal", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			var actual IdentifierURI
			err := json.Unmarshal([]byte(`"`+expected+`"`), &actual)
			if !assert.NoError(t, err) {
				return
			}
			assert.Equal(t, expected, string(actual))
		})
		t.Run("error - invalid PartyID", func(t *testing.T) {
			var actual IdentifierURI
			err := json.Unmarshal([]byte(`"urn:nuts:invalid"`), &actual)
			assert.EqualError(t, err, "invalid PartyID: urn:nuts:invalid")
		})
		t.Run("error - invalid JSON", func(t *testing.T) {
			var actual IdentifierURI
			err := json.Unmarshal([]byte(`failure`), &actual)
			assert.EqualError(t, err, "invalid character 'i' in literal false (expecting 'l')")
		})
	})
}

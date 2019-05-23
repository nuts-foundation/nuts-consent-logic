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

package steps

import (
	"encoding/json"
	"io/ioutil"
	"reflect"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-consent-logic/generated"
)

func TestCreateFhirConsentResource(t *testing.T) {
	type args struct {
		request generated.CreateConsentRequest
	}

	validConsent, err := ioutil.ReadFile("../../test-data/valid-consent.json")
	if err != nil {
		t.Error(err)
	}

	performerId := generated.IdentifierURI("https://nuts.nl/identities/agb#00000003")

	tests := []struct {
		name    string
		args    args
		want    interface{}
		wantErr bool
	}{
		{
			"it can create a valid consent",
			args{
				generated.CreateConsentRequest{
					Subject:   "https://nuts.nl/identities/bsn#999999990",
					Custodian: "https://nuts.nl/identities/agb#00000000",
					Actors: []generated.ActorURI{
						"https://nuts.nl/identities/agb#00000001",
						"https://nuts.nl/identities/agb#00000002",
					},
					Period: &generated.Period{
						Start: time.Date(2019, time.January, 1, 11, 0, 0, 0, time.UTC),
						End:   time.Date(2019, time.July, 1, 11, 0, 0, 0, time.UTC),
					},
					ConsentProof: struct{ generated.EmbeddedData }{
						generated.EmbeddedData{
							Data:        "dhklauHAELrlg78OLg==",
							ContentType: "application/pdf",
						},
					},
					Performer: &performerId,
				},
			},
			string(validConsent),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var o1 interface{}
			var o2 interface{}

			json.Unmarshal(validConsent, &o1)
			got, err := CreateFhirConsentResource(tt.args.request)

			err = json.Unmarshal([]byte(got), &o2)
			if err != nil {
				t.Error(err)
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("CreateFhirConsentResource() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			//if got != tt.want {
			if !reflect.DeepEqual(o1, o2) {

				t.Errorf("CreateFhirConsentResource() = %v, want %v", o1, o2)
			}
		})
	}
}

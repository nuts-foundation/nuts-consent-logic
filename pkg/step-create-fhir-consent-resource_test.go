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
	"encoding/json"
	"gotest.tools/assert"
	"io/ioutil"
	"testing"
	"time"
)

func TestCreateFhirConsentResource(t *testing.T) {
	type args struct {
		request CreateConsentRequest
	}

	validConsent, err := ioutil.ReadFile("../test-data/valid-consent.json")
	if err != nil {
		t.Error(err)
	}

	performerId := IdentifierURI("urn:oid:2.16.840.1.113883.2.4.6.1:00000003")
	url := "https://some.url/reference.pdf"
	contentType := "application/pdf"
	hash := "hash"

	endDate := time.Date(2019, time.July, 1, 11, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		args    args
		want    interface{}
		wantErr bool
	}{
		{
			"it can create a valid consent",
			args{
				CreateConsentRequest{
					Subject:   "urn:oidurn:oid:2.16.840.1.113883.2.4.6.3:999999990",
					Custodian: "urn:oid:2.16.840.1.113883.2.4.6.1:00000000",
					Actor: IdentifierURI(
						"urn:oid:2.16.840.1.113883.2.4.6.1:00000001",
					),
					Records: []Record{{
						Period: Period{
							Start: time.Date(2019, time.January, 1, 11, 0, 0, 0, time.UTC),
							End:   &endDate,
						},
						ConsentProof: &DocumentReference{
							Title:       "title",
							ID:          "id",
							URL:         &url,
							ContentType: &contentType,
							Hash:        &hash,
						},
						DataClass: []IdentifierURI {
							IdentifierURI("urn:oid:1.3.6.1.4.1.XXXXX.1:MEDICAL"),
							IdentifierURI("urn:oid:1.3.6.1.4.1.XXXXX.1:SOCIAL"),
						},
					}},
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

			_ = json.Unmarshal(validConsent, &o1)
			got, err := CreateFhirConsentResource(tt.args.request.Custodian, tt.args.request.Actor, tt.args.request.Subject, *tt.args.request.Performer, tt.args.request.Records[0])
			if err != nil {
				t.Error(err)
			}

			err = json.Unmarshal([]byte(got), &o2)
			if err != nil {
				t.Error(err)
			}

			assert.Equal(t, tt.wantErr, err != nil)
			assert.DeepEqual(t, o1, o2)
		})
	}
}

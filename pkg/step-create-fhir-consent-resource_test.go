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
	"io/ioutil"
	"reflect"
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

	performerId := IdentifierURI("urn:oid:2.16.840.1.113883.2.4.6.3:00000003")

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
					Subject:   "urn:oidurn:oid:2.16.840.1.113883.2.4.6.1:999999990",
					Custodian: "urn:oid:2.16.840.1.113883.2.4.6.3:00000000",
					Actors: []IdentifierURI{
						"urn:oid:2.16.840.1.113883.2.4.6.3:00000001",
						"urn:oid:2.16.840.1.113883.2.4.6.3:00000002",
					},
					Period: &Period{
						Start: time.Date(2019, time.January, 1, 11, 0, 0, 0, time.UTC),
						End:   &endDate,
					},
					ConsentProof: &EmbeddedData{
						Data:        "dhklauHAELrlg78OLg==",
						ContentType: "application/pdf",
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
			if !reflect.DeepEqual(o1, o2) {
				t.Errorf("CreateFhirConsentResource() = %v, want %v", o2, o1)
			}
		})
	}
}

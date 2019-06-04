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
	validationEngine "github.com/nuts-foundation/nuts-fhir-validation/pkg"
	"github.com/spf13/viper"
	"io/ioutil"
	"testing"
)

func Test_validateFhirConsentResource(t *testing.T) {
	viper.Set(validationEngine.ConfigSchemaPath, "../../schema/fhir.schema.json")

	validConsent, err := ioutil.ReadFile("../../test-data/valid-consent.json")
	if err != nil {
		t.Error(err)
	}

	type args struct {
		consentResource string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			"it should validate a schema",
			args{string(validConsent)},
			true,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateFhirConsentResource(tt.args.consentResource)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFhirConsentResource() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ValidateFhirConsentResource() = %v, want %v", got, tt.want)
			}
		})
	}
}

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
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	"testing"
)

func TestGetConsentId(t *testing.T) {
	type args struct {
		request CreateConsentRequest
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"it generates a externalId",
			args{
				request: CreateConsentRequest{Custodian: "agb#00000012"},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			cClient := crypto.NewCryptoClient()
			_ = cClient.GenerateKeyPairFor(types.LegalEntity{URI: string(tt.args.request.Custodian)})

			got, err := GetConsentId(cClient, tt.args.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetConsentId() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(got) != 64 {
				t.Errorf("Expected length of externalId to be 64 got %v instead", len(got))
			}
		})
	}
}

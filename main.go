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

package main

import (
	"github.com/nuts-foundation/nuts-consent-logic/cmd"
)

func main() {
	//cClient := cryptoEngine.NewCryptoClient()
	//cClient.GenerateKeyPairFor(types.LegalEntity{URI: "urn:oid:2.16.840.1.113883.2.4.6.3:00000007"})
	cmd.Execute()
}

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
	"github.com/labstack/gommon/log"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-registry/client"
	"github.com/nuts-foundation/nuts-registry/pkg"
	"sync"
)

type ConsentLogicConfig struct {
}

type ConsentLogic struct {
	NutsRegistry pkg.RegistryClient
	NutsCrypto   crypto.Client
	Config       ConsentLogicConfig
}

var instance *ConsentLogic
var oneEngine sync.Once

func ConsentLogicInstance() *ConsentLogic {
	oneEngine.Do(func() {
		instance = &ConsentLogic{
		}
	})
	return instance
}

func (cl ConsentLogic) StartConsentFlow() {
	log.Debug("starting consent flow")
}

func (ConsentLogic) Configure() error {
	return nil
}

func (cl *ConsentLogic) Start() error {
	cl.NutsCrypto = crypto.NewCryptoClient()
	cl.NutsRegistry = client.NewRegistryClient()
	return nil
}

func (ConsentLogic) Shutdown() error {
	// Stub
	return nil
}

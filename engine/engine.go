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

package engine

import (
	"github.com/deepmap/oapi-codegen/pkg/runtime"
	"github.com/nuts-foundation/nuts-consent-logic/api"
	"github.com/nuts-foundation/nuts-consent-logic/pkg"
	engine "github.com/nuts-foundation/nuts-go/pkg"
	"github.com/spf13/cobra"
	"go/types"
)

func NewConsentLogicEngine() *engine.Engine {
	cl := pkg.ConsentLogicInstance()

	return &engine.Engine{
		Name: "ConsentLogicInstance",
		Cmd: cmd(),
		Start: cl.Start,
		Shutdown: cl.Shutdown,
		Routes: func(router runtime.EchoRouter) {
			api.RegisterHandlers(router, &api.Wrapper{Cl: cl})
		},
	}
}

	return cmd
}

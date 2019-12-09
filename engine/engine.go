/*
 *  Nuts consent logic holds the logic for consent creation
 *  Copyright (C) 2019 Nuts community
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package engine

import (
	"go/types"

	"github.com/deepmap/oapi-codegen/pkg/runtime"
	"github.com/nuts-foundation/nuts-consent-logic/api"
	"github.com/nuts-foundation/nuts-consent-logic/pkg"
	engine "github.com/nuts-foundation/nuts-go-core"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func NewConsentLogicEngine() *engine.Engine {
	cl := pkg.ConsentLogicInstance()

	return &engine.Engine{
		Name:      "ConsentLogicInstance",
		Cmd:       cmd(),
		Configure: cl.Configure,
		Start:     cl.Start,
		ConfigKey: "clogic",
		FlagSet:   flagSet(),
		Shutdown:  cl.Shutdown,
		Routes: func(router runtime.EchoRouter) {
			api.RegisterHandlers(router, &api.Wrapper{Cl: cl})
		},
	}
}

func flagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet("cstore", pflag.ContinueOnError)
	return flags
}

func cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "consent-logic",
		Short: "consent logic commands",
	}

	cmd.AddCommand(&cobra.Command{
		Use:     "create [subject] [custodian] [actors] [performer]? [proof]?",
		Example: "create urn:oid:2.16.840.1.113883.2.4.6.3:999999990 urn:oid:2.16.840.1.113883.2.4.6.1:00000007 urn:oid:2.16.840.1.113883.2.4.6.1:00000001,urn:oid:2.16.840.1.113883.2.4.6.1:00000002",
		Short:   "initiate a new consent record flow for subject, custodian and actors. Actors is comma-seperated",

		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 3 {
				return types.Error{Msg: "requires at least a subject, custodian and actors"}
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			//clc := pkg.NewConsentLogicClient()
			//clc.StartConsentFlow()
			panic("Todo: implement")
		},
	})
	return cmd
}

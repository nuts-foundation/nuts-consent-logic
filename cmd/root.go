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

package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/nuts-foundation/nuts-consent-logic/api"
	"github.com/nuts-foundation/nuts-consent-logic/engine"
	"github.com/nuts-foundation/nuts-consent-logic/pkg"
	engine3 "github.com/nuts-foundation/nuts-consent-store/engine"
	engine4 "github.com/nuts-foundation/nuts-event-octopus/engine"
	nutsgo "github.com/nuts-foundation/nuts-go-core"
	engine2 "github.com/nuts-foundation/nuts-registry/engine"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var serveCommand = &cobra.Command{
	Use:   "serve",
	Short: "Start consent-logic as a standalone api server",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Print: " + strings.Join(args, " "))
		server := echo.New()
		server.HideBanner = true
		server.Use(middleware.Logger())
		instance := pkg.ConsentLogicInstance()
		api.RegisterHandlers(server, api.Wrapper{Cl: instance})
		addr := fmt.Sprintf("%s:%d", serverInterface, serverPort)
		server.Logger.Fatal(server.Start(addr))
	},
}
var (
	serverInterface string
	serverPort      int
)

func init() {
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	nutsConfig := nutsgo.NutsConfig()

	var consentLogicEngine = engine.NewConsentLogicEngine()

	var rootCommand = consentLogicEngine.Cmd
	serveCommand.Flags().StringVar(&serverInterface, confInterface, "localhost", "Server interface binding")
	serveCommand.Flags().IntVarP(&serverPort, confPort, "p", 1324, "Server listen port")
	rootCommand.AddCommand(serveCommand)

	nutsConfig.IgnoredPrefixes = append(nutsConfig.IgnoredPrefixes, consentLogicEngine.ConfigKey)
	nutsConfig.RegisterFlags(rootCommand, consentLogicEngine)

	registryEngine := engine2.NewRegistryEngine()
	nutsConfig.RegisterFlags(rootCommand, registryEngine)

	consentStoreEngine := engine3.NewConsentStoreEngine()
	nutsConfig.RegisterFlags(rootCommand, consentStoreEngine)

	eventOctopusEngine := engine4.NewEventOctopusEngine()
	nutsConfig.RegisterFlags(rootCommand, eventOctopusEngine)

	if err := nutsConfig.Load(rootCommand); err != nil {
		panic(err)
	}

	nutsConfig.PrintConfig(logrus.StandardLogger())

	if err := nutsConfig.InjectIntoEngine(consentLogicEngine); err != nil {
		panic(err)
	}

	if err := nutsConfig.InjectIntoEngine(registryEngine); err != nil {
		panic(err)
	}

	if err := nutsConfig.InjectIntoEngine(consentStoreEngine); err != nil {
		panic(err)
	}

	if err := consentLogicEngine.Configure(); err != nil {
		panic(err)
	}

	if err := eventOctopusEngine.Configure(); err != nil {
		panic(err)
	}

	if err := eventOctopusEngine.Start(); err != nil {
		panic(err)
	}

	if err := registryEngine.Configure(); err != nil {
		panic(err)
	}

	if err := consentLogicEngine.Start(); err != nil {
		panic(err)
	}

	if err := rootCommand.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

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

package cmd

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/nuts-foundation/nuts-consent-logic/api"
	"github.com/nuts-foundation/nuts-consent-logic/engine"
	"github.com/nuts-foundation/nuts-consent-logic/pkg"
	nutsgo "github.com/nuts-foundation/nuts-go/pkg"
	engine2 "github.com/nuts-foundation/nuts-registry/engine"
	"github.com/spf13/cobra"
	"os"
	"strings"
)


var serveCommand = &cobra.Command{
	Use:   "serve",
	Short: "Start consent-logic as a standalone api server",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Print: " + strings.Join(args, " "))
		server := echo.New()
		server.HideBanner = true
		server.Use(middleware.Logger())
		api.RegisterHandlers(server, api.Wrapper{Cl: pkg.ConsentLogicInstance()})
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

	if err := nutsConfig.Load(rootCommand); err != nil {
		panic(err)
	}

	nutsConfig.PrintConfig()

	if err := nutsConfig.InjectIntoEngine(consentLogicEngine); err != nil {
		panic(err)
	}

	if err := nutsConfig.InjectIntoEngine(registryEngine); err != nil {
		panic(err)
	}

	if err := consentLogicEngine.Configure(); err != nil {
		panic(err)
	}

	consentLogicEngine.Start()

	if err := registryEngine.Configure(); err != nil {
		panic(err)
	}

	if err := rootCommand.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

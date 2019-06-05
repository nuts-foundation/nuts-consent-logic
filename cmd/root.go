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
	"os"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var e = engine.NewConsentLogicEngine()
var rootCmd = e.Cmd

var cfgFile string

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {

	rootCmd.AddCommand(&cobra.Command{
		Use:   "serve",
		Short: "Start the consent logic api server",
		Run: func(cmd *cobra.Command, args []string) {
			server := echo.New()
			server.HideBanner = true
			server.Use(middleware.Logger())
			api.RegisterHandlers(server, api.Wrapper{Cl: pkg.ConsentLogicInstance()})
			addr := fmt.Sprintf("%s:%d", viper.GetString(confInterface), viper.GetInt(confPort))
			server.Logger.Fatal(server.Start(addr))
		},
	})

	rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.nuts-consent-logic.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().String(confInterface, "localhost", "Server interface binding")
	rootCmd.Flags().StringP(confPort, "p", "1324", "Server listen port")

	viper.BindPFlag(confPort, rootCmd.Flags().Lookup(confPort))
	viper.BindPFlag(confInterface, rootCmd.Flags().Lookup(confInterface))

	viper.SetEnvPrefix("NUTS_CONSENT_LOGIC")
	viper.BindEnv(confPort)
	viper.BindEnv(confInterface)

}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".nuts-consent-logic" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".nuts-consent-logic")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

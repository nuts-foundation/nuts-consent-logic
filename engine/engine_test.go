package engine

import (
	core "github.com/nuts-foundation/nuts-go-core"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestConsentLogic_Start(t *testing.T) {
	t.Run("start in CLI mode", func(t *testing.T) {
		os.Setenv("NUTS_MODE", core.GlobalCLIMode)
		defer os.Unsetenv("NUTS_MODE")
		core.NutsConfig().Load(&cobra.Command{})
		assert.NoError(t, NewConsentLogicEngine().Start())
	})
}
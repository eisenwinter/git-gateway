package api

import (
	"testing"

	"github.com/eisenwinter/git-gateway/conf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSanitizeOutput(t *testing.T) {

	t.Run("Configuration", func(t *testing.T) {
		v := conf.Configuration{
			GitHub: conf.GitHubConfig{
				AccessToken: "remove",
			},
		}

		ov := sanitizeOutput(v)
		require.IsType(t, v, ov)
		assert.Equal(t, "", ov.(conf.Configuration).GitHub.AccessToken)
	})

	t.Run("ConfigurationPtr", func(t *testing.T) {
		v := &conf.Configuration{
			GitHub: conf.GitHubConfig{
				AccessToken: "remove",
			},
		}

		ov := sanitizeOutput(v)
		require.IsType(t, v, ov)
		assert.Equal(t, "", ov.(*conf.Configuration).GitHub.AccessToken)
	})
}

package cmd

import (
	"context"
	"fmt"

	"github.com/netlify/git-gateway/api"
	"github.com/netlify/git-gateway/conf"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var serveCmd = cobra.Command{
	Use:  "serve",
	Long: "Start API server",
	Run: func(cmd *cobra.Command, args []string) {
		execWithConfig(cmd, serve)
	},
}

func serve(globalConfig *conf.GlobalConfiguration, config *conf.Configuration) {
	ctx, err := api.WithInstanceConfig(context.Background(), config, "")
	if err != nil {
		logrus.Fatalf("Error loading instance config: %+v", err)
	}
	api := api.NewAPIWithVersion(ctx, globalConfig, Version, api.NewKeyFuncResolver(&config.JWT), config.JWT.SigningMethod, config.JWT.ClientID)

	l := fmt.Sprintf("%v:%v", globalConfig.API.Host, globalConfig.API.Port)
	logrus.Infof("git-gateway API started on: %s", l)
	api.ListenAndServe(l)
}

package main

import (
	"log"

	"github.com/eisenwinter/git-gateway/cmd"
)

func main() {
	if err := cmd.RootCommand().Execute(); err != nil {
		log.Fatal(err)
	}
}

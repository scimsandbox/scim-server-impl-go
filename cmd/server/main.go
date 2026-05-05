package main

import (
	"fmt"
	"os"

	"github.com/scimsandbox/scim-server-impl-go/internal/app"
)

func main() {
	if err := app.Run(os.Args[1:], os.Stdout, os.Stderr, nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

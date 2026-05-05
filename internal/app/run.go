package app

import (
	"fmt"
	"io"
	"os"
)

type LookupEnvFunc func(string) (string, bool)

func Run(args []string, stdout, stderr io.Writer, lookupEnv LookupEnvFunc) error {
	if stdout == nil {
		return fmt.Errorf("stdout writer is required")
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}

	command := "serve"
	if len(args) > 0 {
		command = args[0]
	}

	switch command {
	case "serve":
		return serve(stderr, lookupEnv)
	case "healthcheck":
		return healthcheck(lookupEnv)
	case "print-config":
		return printConfig(stdout, lookupEnv)
	default:
		return fmt.Errorf("unknown command: %s", command)
	}
}

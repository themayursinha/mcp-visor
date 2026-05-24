package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/themayursinha/mcp-visor/internal/policy"
	"github.com/themayursinha/mcp-visor/internal/proxy"
)

func main() {
	serveCmd := flag.NewFlagSet("serve", flag.ExitOnError)
	serverCmd := serveCmd.String("server", "", "MCP server command to proxy")
	serverArgs := &stringSlice{}
	serveCmd.Var(serverArgs, "server-arg", "Argument for the MCP server command (repeatable)")
	sessionID := serveCmd.String("session-id", "", "Session identifier")
	clientID := serveCmd.String("client-id", "", "Client identifier")
	policyPath := serveCmd.String("policy", "", "Path to policy YAML file")

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: mcp-visor <command> [options]\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  serve    Start the MCP proxy\n")
		fmt.Fprintf(os.Stderr, "\nRun 'mcp-visor serve -h' for serve options.\n")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		serveCmd.Parse(os.Args[2:])
		if *serverCmd == "" {
			fmt.Fprintf(os.Stderr, "mcp-visor serve: -server is required\n")
			os.Exit(1)
		}

		var pol *policy.Policy
		if *policyPath != "" {
			var err error
			pol, err = policy.LoadFile(*policyPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "mcp-visor: failed to load policy: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Loaded policy: %s (default: %s)\n", *policyPath, pol.DefaultAction)
		} else {
			pol = policy.DefaultPolicy()
			fmt.Fprintf(os.Stderr, "Using default-deny policy\n")
		}

		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()

		p := proxy.New(proxy.Config{
			ServerCommand: *serverCmd,
			ServerArgs:    *serverArgs,
			ClientID:      *clientID,
			SessionID:     *sessionID,
			Policy:        pol,
		})

		if err := p.Run(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "mcp-visor: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

type stringSlice []string

func (s *stringSlice) String() string { return fmt.Sprintf("%v", *s) }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

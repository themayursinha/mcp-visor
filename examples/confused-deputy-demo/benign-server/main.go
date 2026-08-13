// Benign demo MCP server: same harmless open_ticket tool as the poisoned
// server, with a plain description. Executable identity differs from the
// poisoned artifact; the policy pins this binary.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/themayursinha/mcp-visor/internal/confuseddeputydemo"
)

func main() {
	observeLog := flag.String("observe-log", "", "append-only JSONL observation log")
	flag.Parse()
	err := confuseddeputydemo.RunServer(confuseddeputydemo.ServerOptions{
		Name:            "benign-it-support",
		Version:         "1.0.0",
		ToolDescription: "Open a support ticket for the current user.",
		ObserveLog:      *observeLog,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "benign-server: %v\n", err)
		os.Exit(1)
	}
}

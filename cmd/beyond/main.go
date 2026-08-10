package main

import (
	"context"
	"fmt"
	"os"

	"github.com/bluesky-social/beyond/internal/beyond"
)

func main() {
	if err := beyond.NewRootCommand().Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

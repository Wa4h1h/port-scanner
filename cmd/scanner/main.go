package main

import (
	"fmt"
	"os"

	"github.com/Wa4h1h/port-scanner/internal/scanner"
)

func main() {
	c := scanner.NewCli()

	if err := c.Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

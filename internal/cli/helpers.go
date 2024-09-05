package cli

import (
	"fmt"
	"os"
)

func printSpaces(str string) {
	remainingSpaces := 16 - len(str)
	for i := 0; i < remainingSpaces; i++ {
		fmt.Fprint(os.Stdout, " ")
	}
}

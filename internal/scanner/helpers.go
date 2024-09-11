package scanner

import (
	_ "embed"
	"fmt"
	"os"
)

//go:embed assets/service-names-port-numbers.csv
var svcNamesPort []byte

func printSpaces(str string) {
	remainingSpaces := 16 - len(str)
	for i := 0; i < remainingSpaces; i++ {
		fmt.Fprint(os.Stdout, " ")
	}
}

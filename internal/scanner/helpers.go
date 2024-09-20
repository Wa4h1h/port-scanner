package scanner

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

func printHeader() {
	header := "PORT\t\tSTATE\t\tSERVICE"
	fmt.Fprintln(os.Stdout, header)
}

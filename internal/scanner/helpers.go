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
	fmt.Fprintln(os.Stdout, "PORT\t\tSTATE\t\tSERVICE")
}

func printErrors(errs []error) {
	if len(errs) > 0 {
		fmt.Fprintln(os.Stdout, "------------ ")
		for _, err := range errs {
			fmt.Fprintln(os.Stderr, err)
		}
		fmt.Fprintln(os.Stdout, "------------ \n")
	}
}

func printFooter(hosts int, rtt float64) {
	fmt.Fprintf(os.Stdout, "\ndone scanning %d host(s) in %.2fs",
		hosts, rtt)
}

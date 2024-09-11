package main

import (
	"fmt"

	"github.com/Wa4h1h/networki/pkg/ping"
)

func main() {
	/*c := scanner.NewCli()

	if err := c.Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}*/

	p := ping.NewPinger(&ping.DefaultConfig, ping.WithNumPings(10))

	s, err := p.Ping("142.251.36.14")
	if err != nil {
		panic(err)
	}

	fmt.Println(s.Up)
	fmt.Println(s.Rtt)
	fmt.Println(s.RDns)
	fmt.Println(s.NSent)
	fmt.Println(s.NReceived)
	fmt.Println(s.PacketLoss)
}

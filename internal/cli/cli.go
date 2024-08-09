package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/Wa4h1h/port-scanner/pkg/scanner"
)

var (
	ports      string
	hosts      string
	tcp        bool
	udp        bool
	vanilla    bool
	syn        bool
	timeout    int
	cscan      int
	useDefault bool
)

func init() {
	flag.StringVar(&ports, "p", "", "ports to scan")
	flag.StringVar(&hosts, "hosts", "", "hosts/ips to scan")
	flag.BoolVar(&vanilla, "v", false, "scan all 65535 ports")
	flag.BoolVar(&syn, "syn", false, "enable tcp syn scan")
	flag.BoolVar(&tcp, "T", true, "run tcp scan")
	flag.BoolVar(&udp, "U", false, "run udp scan")
	flag.IntVar(&timeout, "tS", scanner.DefaultTimeout, "port scan timeout in seconds")
	flag.IntVar(&cscan, "cS", scanner.DefaultCScan, "number of concurrent port scans")
	flag.BoolVar(&useDefault, "dS", true, "use default scanner config")
}

type Cli struct{}

func NewCli() *Cli {
	return &Cli{}
}

func (c *Cli) Parse() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stdout, `Usage: pscan [options]
Use pscan -h or --help for more information.`)
		fmt.Fprintln(os.Stdout, "Options:")
		flag.PrintDefaults()
	}

	flag.Parse()

	if hosts == "" {
		fmt.Fprintln(os.Stderr, "hosts are missing: provide at least one host/ip")
		os.Exit(1)
	}
}

func (c *Cli) Run() error {
	return nil
}

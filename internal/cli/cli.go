package cli

import (
	"flag"
	"fmt"
	"os"
)

func init() {
}

type settings struct {
	ports      string
	hosts      string
	timeout    int
	cscan      int
	tcp        bool
	udp        bool
	vanilla    bool
	syn        bool
	useDefault bool
}

type Cli struct {
	flags *flag.FlagSet
	s     *settings
}

func NewCli() *Cli {
	return &Cli{
		s: new(settings),
	}
}

func (c *Cli) registerFlags() {
	c.flags = flag.NewFlagSet("pscan", flag.ExitOnError)

	c.flags.StringVar(&c.s.ports, "p", Ports, "ports to scan")
	c.flags.StringVar(&c.s.hosts, "hosts", "", "hosts/ips to scan")
	c.flags.BoolVar(&c.s.vanilla, "v", Vanilla, "scan all 65535 ports")
	c.flags.BoolVar(&c.s.syn, "syn", SYN, "enable tcp syn scan")
	c.flags.BoolVar(&c.s.tcp, "T", TCP, "run tcp scan")
	c.flags.BoolVar(&c.s.udp, "U", UDP, "run udp scan")
	c.flags.IntVar(&c.s.timeout, "tS", DefaultTimeout, "port scan timeout in seconds")
	c.flags.IntVar(&c.s.cscan, "cS", DefaultCScan, "number of concurrent port scans")
	c.flags.BoolVar(&c.s.useDefault, "dS", UseDefaultSettings, "use default scanner config")
}

func (c *Cli) parse(args []string) error {
	c.registerFlags()
	c.flags.Usage = func() {
		fmt.Fprintln(os.Stdout, `Usage: pscan [options]
Use pscan -h or --help for more information.`)
		fmt.Fprintln(os.Stdout, "Options:")
		c.flags.PrintDefaults()
	}

	if err := c.flags.Parse(args); err != nil {
		return fmt.Errorf("error: parse args: %w", err)
	}

	if c.s.hosts == "" {
		return ErrHostsMissing
	}

	return nil
}

func (c *Cli) Run(args []string) error {
	if err := c.parse(args); err != nil {
		return err
	}

	return nil
}

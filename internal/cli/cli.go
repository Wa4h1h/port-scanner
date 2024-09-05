package cli

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Wa4h1h/port-scanner/pkg/scanner"
)

type settings struct {
	ports      string
	hosts      string
	timeout    int
	cscan      int
	retries    int
	tcp        bool
	udp        bool
	vanilla    bool
	syn        bool
	privileged bool
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
	c.flags.BoolVar(&c.s.privileged, "pv", false,
		"set pv(privileged) to true using ping with icmp instead of udp")
	c.flags.IntVar(&c.s.retries, "sr", scanner.DefaultRetries,
		"number of scan retires before the scan is considered filtered")
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

	cfg := scanner.Config{
		TCP:     c.s.tcp,
		UDP:     c.s.udp,
		SYN:     c.s.syn,
		Timeout: c.s.timeout,
		CScan:   c.s.cscan,
		Retries: c.s.retries,
	}
	s := scanner.NewScanExecutor(&cfg, c.s.privileged)
	hosts := strings.Split(c.s.hosts, ",")
	ports := strings.Split(c.s.ports, ",")

	start := time.Now()

	switch {
	case len(hosts) > 1:
		if len(ports) == 1 && ports[0] != "" {
			sweepScanResults, err := s.SweepScan(hosts, ports[0])
			if err != nil {
				return err
			}

			c.printSweepScanResults(sweepScanResults)
		} else {
			fmt.Fprintln(os.Stderr, "provide at least one port to sweep scan")
		}
	case len(hosts) == 1:
		port := ports[0]
		scanResults := make([]*scanner.ScanResult, 0)

		var err error

		switch {
		case len(ports) == 1:
			if port != "" {
				rangeCheck := strings.Contains(port, "-")
				if rangeCheck {
					var (
						start int
						end   int
					)

					rangeStr := strings.Split(port, "-")
					if len(rangeStr) != 2 {
						return ErrRangeStrLength
					}

					rangePorts := make([]string, 0)

					start, err = strconv.Atoi(rangeStr[0])
					if err != nil {
						return err
					}

					end, err = strconv.Atoi(rangeStr[1])
					if err != nil {
						return err
					}

					for i := start; i <= end; i++ {
						rangePorts = append(rangePorts, fmt.Sprintf("%d", i))
					}

					scanResults, err = s.RangeScan(hosts[0], rangePorts)
					if err != nil {
						return err
					}
				} else {
					var tmp []*scanner.ScanResult

					if cfg.SYN {
						tmp, err = s.SynScan(hosts[0], port)
						if err != nil {
							return err
						}

						scanResults = append(scanResults, tmp...)
					}

					tmp, err = s.Scan(hosts[0], port)
					if err != nil {
						return err
					}

					scanResults = append(scanResults, tmp...)
				}
			} else {
				scanResults, err = s.VanillaScan(hosts[0])
				if err != nil {
					return err
				}
			}
		case len(ports) > 1:
			scanResults, err = s.RangeScan(hosts[0], ports)
			if err != nil {
				return err
			}

		}

		end := time.Now().Sub(start)
		fmt.Fprintln(os.Stdout, "PORT\t\tSTATE\t\tSERVICE")
		for _, res := range scanResults {
			c.printScanResults(res)
		}
		fmt.Println(fmt.Sprintf("\ndone scanning %d host(s) in %.2fs", len(hosts), end.Seconds()))
	}

	return nil
}

func (c *Cli) printSweepScanResults(results []*scanner.SweepScanResult) {}

func (c *Cli) printScanResults(result *scanner.ScanResult) {
	fmt.Fprintf(os.Stdout, "%s", result.Port)
	printSpaces(result.Port)
	fmt.Fprint(os.Stdout, result.State)
	printSpaces(string(result.State))
	fmt.Fprintf(os.Stdout, "%s\n", result.Service)
}

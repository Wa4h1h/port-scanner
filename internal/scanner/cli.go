package scanner

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Wa4h1h/port-scanner/pkg/ping"

	"github.com/Wa4h1h/port-scanner/pkg/scanner"
)

type settings struct {
	ports        string
	hosts        string
	timeout      int
	cscan        int
	backOffLimit int
	tcp          bool
	udp          bool
	vanilla      bool
	syn          bool
	privileged   bool
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
		"set pv(privileged) to true which allows using ping with raw socket type instead of dgram socket type")
	c.flags.IntVar(&c.s.backOffLimit, "sr", scanner.DefaultBackoffLimit,
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
		TCP:          c.s.tcp,
		UDP:          c.s.udp,
		SYN:          c.s.syn,
		Timeout:      c.s.timeout,
		CScan:        c.s.cscan,
		BackoffLimit: c.s.backOffLimit,
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
		host := hosts[0]
		scanResults := make([]*scanner.ScanResult, 0)

		var (
			err       error
			pingStats = new(ping.Stats)
		)

		switch {
		case len(ports) == 1:
			if port == "" {
				pingStats, scanResults, err = s.VanillaScan(host)
				if err != nil {
					return err
				}
			}

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

				pingStats, scanResults, err = s.RangeScan(host, rangePorts)
				if err != nil {
					return err
				}
			} else {
				var tmp []*scanner.ScanResult

				pingStats, host, err = s.PingHost(host)
				if err != nil {
					return err
				}

				if cfg.SYN {
					pingStats, tmp, err = s.SynScan(host, port)
					if err != nil {
						return err
					}

					scanResults = append(scanResults, tmp...)
				}

				tmp, err = s.Scan(host, port)
				if err != nil {
					return err
				}

				scanResults = append(scanResults, tmp...)
			}

		case len(ports) > 1:
			pingStats, scanResults, err = s.RangeScan(host, ports)
			if err != nil {
				return err
			}

		}

		end := time.Now().Sub(start)

		c.printPing(host, pingStats)
		printHeader()

		for _, res := range scanResults {
			c.printScanResult(res)
		}

		fmt.Fprintf(os.Stdout, "\ndone scanning %d host(s) in %.2fs", len(hosts), end.Seconds())
	}

	return nil
}

func (c *Cli) printSweepScanResults(results []*scanner.SweepScanResult) {
	for _, res := range results {
		c.printPing(res.Host, res.PingStats)
		printHeader()
		c.printScanResult(&res.ScanResult)
	}
}

func (c *Cli) printPing(host string, pingStats *ping.Stats) {
	fmt.Fprintf(os.Stdout, "Scanning %s(%s)\n", host, pingStats.IP)
	fmt.Fprintf(os.Stdout, "%s is Up: %.2fs\n", pingStats.IP, pingStats.Rtt)
	fmt.Fprintf(os.Stdout, "rDNS: %s\n", pingStats.RDns)
}

func (c *Cli) printScanResult(result *scanner.ScanResult) {
	fmt.Fprintf(os.Stdout, "%s", result.Port)
	printSpaces(result.Port)
	fmt.Fprint(os.Stdout, result.State)
	printSpaces(string(result.State))
	fmt.Fprintf(os.Stdout, "%s\n", result.Service)
}

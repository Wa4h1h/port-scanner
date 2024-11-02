package scanner

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Wa4h1h/port-scanner/pkg/dns"

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
	ping         bool
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
	c.flags = flag.NewFlagSet("scanner", flag.ExitOnError)

	c.flags.StringVar(&c.s.ports, "p", Ports, "ports to scan")
	c.flags.StringVar(&c.s.hosts, "hosts", "", "hosts/ips to scan")
	c.flags.BoolVar(&c.s.vanilla, "v", Vanilla, "scan all 65535 ports")
	c.flags.BoolVar(&c.s.syn, "syn", SYN, "enable tcp syn scan")
	c.flags.BoolVar(&c.s.tcp, "T", TCP, "run tcp scan")
	c.flags.BoolVar(&c.s.udp, "U", UDP, "run udp scan")
	c.flags.IntVar(&c.s.timeout, "tS", DefaultTimeout, "port scan timeout in seconds")
	c.flags.BoolVar(&c.s.privileged, "pv", false,
		"set pv(privileged) to true which allows using ping with raw socket type instead of dgram socket type")
	c.flags.IntVar(&c.s.backOffLimit, "sr", scanner.DefaultBackoffLimit,
		"number of scan retires before the scan is considered filtered")
	c.flags.BoolVar(&c.s.ping, "pg", Ping, "ping before scanning")
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

func (c *Cli) setConfig(args []string) *scanner.Config {
	if err := c.parse(args); err != nil {
		panic(err)
	}

	cfg := scanner.Config{
		TCP:          c.s.tcp,
		UDP:          c.s.udp,
		SYN:          c.s.syn,
		Timeout:      c.s.timeout,
		BackoffLimit: c.s.backOffLimit,
		Ping:         c.s.ping,
	}

	return &cfg
}

func (c *Cli) Run(args []string) error {
	cfg := c.setConfig(args)
	s := scanner.NewScanExecutor(cfg, c.s.privileged)

	hosts := strings.Split(c.s.hosts, ",")
	ports := strings.Split(c.s.ports, ",")

	switch {
	case len(hosts) > 1:
		if len(ports) == 1 && ports[0] != "" {
			sweepScanResults, rtt := s.SweepScan(hosts, ports[0])

			c.printSweepScanResults(sweepScanResults, rtt)
		} else {
			fmt.Fprintln(os.Stderr, "provide only one port to sweep scan")
		}
	case len(hosts) == 1:
		port := ports[0]
		host := hosts[0]
		scanResults := make([]*scanner.ScanResult, 0)

		var (
			errs  []error
			err   error
			stats *scanner.Stats
		)

		switch {
		case len(ports) == 1:
			if port == "" || c.s.vanilla {
				scanResults, stats, errs = s.VanillaScan(host)

				printErrors(errs)

				break
			}

			rangeCheck := strings.Contains(port, "-")

			if rangeCheck {
				var (
					startPort int
					endPort   int
				)

				rangeStr := strings.Split(port, "-")
				if len(rangeStr) != 2 {
					return ErrRangeStrLength
				}

				rangePorts := make([]string, 0)

				startPort, err = strconv.Atoi(rangeStr[0])
				if err != nil {
					return err
				}

				endPort, err = strconv.Atoi(rangeStr[1])
				if err != nil {
					return err
				}

				for i := startPort; i <= endPort; i++ {
					rangePorts = append(rangePorts, fmt.Sprintf("%d", i))
				}

				scanResults, stats, errs = s.Scan(host, rangePorts)

				printErrors(errs)
			} else {
				scanResults, stats, errs = s.Scan(host, ports)

				printErrors(errs)
			}

		case len(ports) > 1:
			scanResults, stats, errs = s.Scan(host, ports)

			printErrors(errs)
		}

		if len(scanResults) != 0 {
			c.printResults(host, stats, scanResults)
		}

		if stats != nil {
			printFooter(len(scanResults), stats.Rtt)
		}
	}

	return nil
}

func (c *Cli) printSweepScanResults(results []*scanner.SweepScanResult, rtt float64) {
	var accRes int

	for _, res := range results {
		if len(res.Errs) != 0 {
			fmt.Fprintf(os.Stdout, "-----scanning %s aborted-----\n",
				res.Host)
			printErrors(res.Errs)

			continue
		}

		c.printResults(res.Host,
			res.Stats, res.ScanResults)

		accRes++

		fmt.Println()
	}

	printFooter(accRes, rtt)
}

func (c *Cli) printDnsInfo(host string, dnsInfo *dns.DNSInfo) {
	fmt.Fprintf(os.Stdout, "-----scanning %s(%s)-----\n", host, dnsInfo.IP)
	fmt.Fprintf(os.Stdout, "rDNS: %s\n", dnsInfo.RDns)
}

func (c *Cli) printPing(host string, pingStats *ping.Stats) {
	fmt.Fprintf(os.Stdout, "-----ping %s(%s) stats-----\n", host, pingStats.DnsInfo.IP)
	fmt.Fprintf(os.Stdout, "%s is Up: %.2fs\n", pingStats.DnsInfo.IP, pingStats.Rtt)
	fmt.Fprintf(os.Stdout, "%d packets transmitted, %d packets received, %.2f packet loss\n",
		pingStats.NSent, pingStats.NReceived, pingStats.PacketLoss)
	fmt.Fprintf(os.Stdout, "round-trip avg = %.2fs\n", pingStats.Rtt)
}

func (c *Cli) printScanResult(result *scanner.ScanResult) {
	fmt.Fprintf(os.Stdout, "%s", result.Port)
	printSpaces(result.Port)
	fmt.Fprint(os.Stdout, result.State)
	printSpaces(string(result.State))
	fmt.Fprintf(os.Stdout, "%s\n", result.Service)
}

func (c *Cli) printResults(host string, stats *scanner.Stats,
	scanResults []*scanner.ScanResult,
) {
	if stats != nil {
		if stats.Ping != nil {
			c.printPing(host, stats.Ping)
		}

		if stats.DNS != nil {
			c.printDnsInfo(host, stats.DNS)
		}
	}

	printHeader()

	for _, res := range scanResults {
		c.printScanResult(res)
	}
}

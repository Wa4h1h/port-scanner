# port-scanner
A port scanner implemented in go. This repository contains a port scanner and ping go packages.

## Using scanner package
##### Note: syn scanning requires raw-packet privileges
#### simple scan:
scan one host and one or multiple ports
```go
import "github.com/Wa4h1h/port-scanner/pkg/scanner"

func main (){
	cfg := scanner.Config{
        TCP:          true,
        UDP:          true,
        SYN:          true,
        Timeout:      1, // in seconds
        BackoffLimit: 5,
        Ping:         true, // before each scan, the host is pinged
    }

    privileged:=false // If true, a raw socket is used to perform the ping, otherwise a simple Dgram socket is used
    s := scanner.NewScanExecutor(&cfg, privileged)
    
	host:="google.com"
	ports:=[]string{"80"}
	
    scanResults, stats, errs = s.Scan(host, ports)
}
```
#### sweep scan:
scan multiple host and only one port
```go
import "github.com/Wa4h1h/port-scanner/pkg/scanner"

func main (){
	cfg := scanner.Config{
        TCP:          true,
        UDP:          true,
        SYN:          true,
        Timeout:      1, // in seconds
        BackoffLimit: 5,
        Ping:         true, // before each scan, the host is pinged
    }

    privileged:=false // If true, a raw socket is used to perform the ping, otherwise a simple Dgram socket is used
    s := scanner.NewScanExecutor(&cfg, privileged)
    
	hosts:=[]string{"google.com","127.0.0.1"}
	port:="80"

    sweepScanResults, rtt := s.SweepScan(hosts, port)
}
```
#### vanilla scan:
scan one host and all the iana ports (0-65535)
```go
import "github.com/Wa4h1h/port-scanner/pkg/scanner"

func main (){
	cfg := scanner.Config{
        TCP:          true,
        UDP:          true,
        SYN:          true,
        Timeout:      1, // in seconds
        BackoffLimit: 5,
        Ping:         true, // before each scan, the host is pinged
    }

    privileged:=false // If true, a raw socket is used to perform the ping, otherwise a simple Dgram socket is used
    s := scanner.NewScanExecutor(&cfg, privileged)
	
	host:="google.com"

	scanResults, stats, errs = s.VanillaScan(host)
}
```
#### Using the CLI to perform port scan
Usage:
```bash
Usage: scanner [options]
Use scanner -h or --help for more information.
Options:
  -T    run tcp scan (default true)
  -U    run udp scan
  -hosts string
        hosts/ips to scan
  -p string
        ports to scan
  -pg
        ping before scanning
  -pv
        set pv(privileged) to true which allows using ping with raw socket type instead of dgram socket type
  -sr int
        number of scan retires before the scan is considered filtered (default 3)
  -syn
        enable tcp syn scan
  -tS int
        port scan timeout in seconds (default 1)
  -v    scan all 65535 ports
```

#### Example Syn range scan with ping enabled
```bash
sudo go run main.go -U=false -T=false -syn=true  -hosts=scanme.nmap.org -pg=true -p=22-27

-----ping scanme.nmap.org(45.33.32.156) stats-----
45.33.32.156 is Up: 0.49s
3 packets transmitted, 3 packets received, 0.00 packet loss
round-trip avg = 0.49s
-----scanning scanme.nmap.org(45.33.32.156)-----
rDNS: scanme.nmap.org.
PORT            STATE           SERVICE
22/tcp          open            ssh
23/tcp          closed          telnet
24/tcp          closed          24/tcp
25/tcp          closed          smtp
26/tcp          closed          26/tcp
27/tcp          closed          nsw-fe

done scanning 6 host(s) in 1.02s
```
## Using ping package
##### Note: ping package can be used in two modes privileged(raw-sockets)
##### and unprivileged(dgram-sockets):
```go
import "github.com/Wa4h1h/port-scanner/pkg/ping"

func main() {
    cfg := ping.Config{
        Timeout:      1, // insecond
        PingNum:      3, // number of pings to perform
        Privileged:   false,
        BackoffLimit: 5,
        Cping:        3,  // number of concurrent pings
        DelayRetry:   15, // in milliseconds
    }
    
    p := ping.NewPinger(&cfg)
    
    stats, err := p.Ping("google.com")
}
```

##### NOTE: I wrote this library for learning purposes. It may not be completely thought out and error free. Use at Your Own Risk.
# port-scanner
A port scanner implemented in go. This repository contains a port scanner, ping and tcp packet builder go packages.

## Using scanner package
#### simple scan
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
    s := scanner.NewScanExecutor(cfg, privileged)
    
	host:="google.com"
	ports:=[]string{"80"}
	
    scanResults, stats, errs = s.Scan(host, ports)
}
```
#### sweep scan
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
    s := scanner.NewScanExecutor(cfg, privileged)
    
	hosts:=[]string{"google.com","127.0.0.1"}
	port:="80"

    sweepScanResults, rtt := s.SweepScan(hosts, port)
}
```
#### vanilla scan
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
    s := scanner.NewScanExecutor(cfg, privileged)
	
	host:="google.com"

	scanResults, stats, errs = s.VanillaScan(host)
}
```
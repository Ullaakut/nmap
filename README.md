# nmap

<p>
    <a href="LICENSE">
        <img src="https://img.shields.io/badge/license-MIT-blue.svg?style=flat" />
    </a>
    <a href="https://godoc.org/github.com/Ullaakut/nmap">
        <img src="https://godoc.org/github.com/Ullaakut/cameradar?status.svg" />
    </a>
    <a href="https://goreportcard.com/report/github.com/ullaakut/nmap">
        <img src="https://goreportcard.com/badge/github.com/ullaakut/nmap">
    </a>
<p>

This library aims at providing idiomatic `nmap` bindings for go developers, in order to make it easier to write security audit tools using golang.

<!-- It allows not only to parse the XML output of nmap, but also to get the output of nmap as it is running, through a channel. This can be useful for computing a scan's progress, or simply displaying live information to your users. -->

## It's currently a work in progress

This paragraph won't be removed until the library is ready to be used and properly documented.

## Supported features

- [x] All of `nmap`'s options as `WithXXX` methods.
- [x] Cancellable contexts support.
- [x] [Idiomatic go filters](examples/service_detection/main.go#L19).
- [x] Helpful enums for most nmap commands. (time templates, os families, port states, etc.)
- [x] Complete documentation of each option, mostly insipred from nmap's documentation.
- [ ] Examples of usage - Work in progress

## TODO

- [ ] Complete unit tests
- [ ] CI
- [ ] Coveralls
- [ ] Asynchronous scan
- [ ] Abort/Resume scans

## Example

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/Ullaakut/nmap"
)

func main() {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
    defer cancel()

    // Equivalent to `/usr/local/bin/nmap -p 554,8554,18554-18654 172.17.100.0/24`,
    // with a 5 minute timeout.
    scanner, err := nmap.New(
        nmap.WithBinaryPath("/usr/local/bin/nmap"),
        nmap.WithTarget("172.17.100.0/24"),
        nmap.WithPorts("554,8554,18554-18654"),
        nmap.WithContext(ctx),
    )
    if err != nil {
        log.Fatalf("unable to create nmap scanner: %v", err)
    }

    result, err := scanner.Run()
    if err != nil {
        log.Fatalf("unable to run nmap scan: %v", err)
    }

    // Use the results to print an example output
    for _, host := range result.Hosts {
        if len(host.Ports) == 0 || len(host.Addresses) == 0 {
            continue
        }

        fmt.Printf("Host %q:\n", host.Addresses[0])

        for _, port := range host.Ports {
            fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
        }
    }

    fmt.Printf("Nmap done: %d hosts up scanned in %3f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
}
```

The program above outputs:

```bash
Host "172.17.100.65":
    Port 554/tcp open rtsp
    Port 8554/tcp open rtsp-alt
    Port 18554/tcp open unknown

Host "172.17.100.70":
    Port 554/tcp open rtsp
    Port 8554/tcp open rtsp-alt
    Port 18554/tcp open unknown

Host "172.17.100.72":
    Port 554/tcp open rtsp
    Port 8554/tcp open rtsp-alt
    Port 18554/tcp open unknown

Nmap done: 3 hosts up scanned in 6.15 seconds
```

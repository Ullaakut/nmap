# nmap

<p align="center">
    <img width="350" src="img/logo.png"/>
<p>

<p align="center">
    <a href="LICENSE">
        <img src="https://img.shields.io/badge/license-MIT-blue.svg?style=flat" />
    </a>
    <a href="https://pkg.go.dev/github.com/Ullaakut/nmap/v4"><img src="https://pkg.go.dev/badge/github.com/Ullaakut/nmap/v4" alt="PkgGoDev github.com/Ullaakut/nmap/v4"></a>
    <a href="https://goreportcard.com/report/github.com/Ullaakut/nmap/v4">
        <img src="https://goreportcard.com/badge/github.com/Ullaakut/nmap/v4">
    </a>
    <a href="https://github.com/Ullaakut/nmap/actions/workflows/build.yml">
        <img src="https://github.com/Ullaakut/nmap/actions/workflows/build.yml/badge.svg">
    </a>
    <a href="https://github.com/Ullaakut/nmap/actions/workflows/test.yml">
        <img src="https://github.com/Ullaakut/nmap/actions/workflows/test.yml/badge.svg">
    </a>
    <a href='https://coveralls.io/github/Ullaakut/nmap'>
        <img src='https://coveralls.io/repos/github/Ullaakut/nmap/badge.svg' alt='Coverage Status' />
    </a>

<p>

This library aims at providing idiomatic `nmap` bindings for go developers, in order to make it easier to write security audit tools using golang.

## What is nmap

Nmap (Network Mapper) is a free and open-source network scanner created by [Gordon Lyon](https://en.wikipedia.org/wiki/Gordon_Lyon). Nmap is used to discover hosts and services on a computer network by sending packets and analyzing the responses.

Nmap provides a number of features for probing computer networks, including host discovery and service and operating system detection. These features are extensible by scripts that provide more advanced service detection, vulnerability detection, and other features. Nmap can adapt to network conditions including latency and congestion during a scan.

## Why use Go for penetration testing

Most pentest tools are currently written using Python and not Go, because it is easy to quickly write scripts, lots of libraries are available, and it's a simple language to use. However, for writing robust and reliable applications, Go is the better tool. It is statically compiled, has a static type system, much better performance, it is also a very simple language to use and goroutines are awesome... But I might be slighly biased, so feel free to disagree.

## How it works

This library shells out to the `nmap` binary using Go's `exec` package and parses the XML output.
That means `nmap` must be installed and available on your PATH for this library to work.

Compatibility is confirmed with the current latest version of nmap, `7.98`.

## Privileges

Some scan types require elevated privileges (for example, SYN scans, OS detection, or raw socket usage).
If you enable those options, you may need to run your program with sudo or the appropriate capabilities for your platform.

> [!TIP]
> For unprivileged runs, prefer connect scans (e.g. `-sT`).

## Examples

### Synchronous scan

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Ullaakut/nmap/v4"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Equivalent to `/usr/local/bin/nmap -p 80,443,843 google.com facebook.com youtube.com`,
	// with a 5-minute timeout.
	scanner, err := nmap.NewScanner(
		nmap.WithTargets("scanme.nmap.org"),
		nmap.WithPorts("80,443,843"),
	)
	if err != nil {
		log.Fatalf("creating nmap scanner: %v", err)
	}

	result, err := scanner.Run(ctx)
	if err != nil {
		log.Fatalf("running network scan: %v", err)
	}

	warnings := result.Warnings()
	if len(warnings) > 0 {
		log.Printf("warning: %v\n", warnings) // Warnings are non-critical errors from nmap.
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

	fmt.Printf("Nmap done: %d hosts up scanned in %.2f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
}
```

The program above outputs:

```bash
Host "45.33.32.156":
	Port 80/tcp open http
	Port 443/tcp closed https
	Port 843/tcp closed 
Nmap done: 1 hosts up scanned in 0.42 seconds
```

### Synchronous scan with progress (TTY only)

> [!IMPORTANT]
> This relies on terminal escape sequences and only works when the process is attached to a TTY.

> [!NOTE]
> Progress is not guaranteed to increase monotonically: nmap estimates time remaining and can revise that estimate, which may cause the reported percentage to go down.

```go
package main

import (
	"context"
	"log"
	"time"

	"github.com/Ullaakut/nmap/v4"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	scanner, err := nmap.NewScanner(
		nmap.WithTargets("scanme.nmap.org"),
		nmap.WithPorts("1-1024"),
		nmap.WithTimingTemplate(nmap.TimingAggressive),
		nmap.WithProgress(time.Second, handleProgress),
	)
	if err != nil {
		log.Fatalf("creating nmap scanner: %v", err)
	}

	_, err = scanner.Run(ctx)
	if err != nil {
		log.Fatalf("running network scan: %v", err)
	}
}

func handleProgress(p nmap.TaskProgress) {
	log.Println("Current progress: ", p.Percent)
}
```

This example outputs the following:

```txt
2026/01/27 16:13:02 task "Connect Scan": 2.59% remaining 38
2026/01/27 16:13:02 task "Connect Scan": 21.26% remaining 4
2026/01/27 16:13:04 task "Connect Scan": 42.61% remaining 5
2026/01/27 16:13:04 task "Connect Scan": 45.51% remaining 4
2026/01/27 16:13:05 task "Connect Scan": 53.44% remaining 4
2026/01/27 16:13:07 task "Connect Scan": 59.77% remaining 5
2026/01/27 16:13:07 task "Connect Scan": 62.77% remaining 4
2026/01/27 16:13:08 task "Connect Scan": 73.24% remaining 3
2026/01/27 16:13:09 task "Connect Scan": 81.71% remaining 2
2026/01/27 16:13:10 task "Connect Scan": 92.92% remaining 1
2026/01/27 16:13:11 task "Connect Scan": 100.00% remaining 0
```

### Asynchronous scan

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Ullaakut/nmap/v4"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	scanner, err := nmap.NewScanner(
		nmap.WithTargets("scanme.nmap.org"),
		nmap.WithPorts("1-1024"),
	)
	if err != nil {
		log.Fatalf("creating nmap scanner: %v", err)
	}

	stdout, stderr, resultCh, err := scanner.RunAsync(ctx)
	if err != nil {
		log.Fatalf("running network scan: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			log.Fatalf("scan timed out: %v", ctx.Err())
		case out := <-stdout:
			fmt.Printf("nmap output: %s\n", out)
		case errOut := <-stderr:
			fmt.Printf("nmap error output: %s\n", errOut)
		case result := <-resultCh:
			if result.Err != nil {
				log.Fatalf("running network scan: %v", result.Err)
			}

			fmt.Printf("Nmap done: %d hosts up\n", len(result.Result.Hosts))
			return
		}
	}
}
```

### More examples

See the [examples](examples/) directory for more usage examples.

## Advanced example

[Cameradar](https://github.com/Ullaakut/cameradar) already uses this library at its core to communicate with nmap, discover RTSP streams and access them remotely.

More examples:

- [Basic scan](examples/basic_scan/main.go)
- [Count hosts for each operating system on a network](examples/count_hosts_by_os/main.go)
- [Service detection](examples/service_detection/main.go)
- [IP address spoofing and decoys](examples/spoof_and_decoys/main.go)
- [List local interfaces](examples/list_interfaces/main.go)

## External resources

- [Official nmap documentation](https://nmap.org/docs.html)
- [Nmap reference guide](https://nmap.org/book/man.html)

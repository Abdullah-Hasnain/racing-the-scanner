// GC-heavy allocator loop. The Go runtime returns memory with MADV_DONTNEED /
// MADV_FREE when the scavenger runs.
// Usage: go build -o gcstress gcstress.go && ./gcstress -seconds 30
package main

import (
	"flag"
	"fmt"
	"runtime/debug"
	"time"
)

var sink [][]byte

func main() {
	seconds := flag.Float64("seconds", 30, "how long to run")
	flag.Parse()

	end := time.Now().Add(time.Duration(*seconds * float64(time.Second)))
	rounds := 0
	for time.Now().Before(end) {
		for i := 0; i < 256; i++ {
			b := make([]byte, 256<<10)
			b[0] = byte(i)
			sink = append(sink, b)
		}
		sink = nil
		if rounds%4 == 0 {
			debug.FreeOSMemory() // forces a GC and scavenges to the OS
		}
		rounds++
	}
	fmt.Printf("[benign-go] %d rounds\n", rounds)
}

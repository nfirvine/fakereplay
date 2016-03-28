package main

// Parses a pcap file, writes it back to disk, then verifies the files
// are the same.
import (
	"bufio"
	"flag"
	"log"
	"os"
	"time"

	"github.com/miekg/pcap"
)

var input *string = flag.String("input", "", "input file")
var output *string = flag.String("output", "", "output file")
var decode *bool = flag.Bool("decode", false, "print decoded packets")
var l = log.New(os.Stderr, "", 0)
var delayScale *uint = flag.Uint("delayscale", 5, "slow down time by this factor")

func copyPcap(dest, src string) {
	f, err := os.Open(src)
	if err != nil {
		l.Printf("couldn't open %q: %v\n", src, err)
		return
	}
	defer f.Close()
	reader, err := pcap.NewReader(bufio.NewReader(f))
	if err != nil {
		l.Printf("couldn't create reader: %v\n", err)
		return
	}
	w, err := os.Create(dest)
	if err != nil {
		l.Printf("couldn't open %q: %v\n", dest, err)
		return
	}
	defer w.Close()
	buf := bufio.NewWriter(w)
	writer, err := pcap.NewWriter(buf, &reader.Header)
	if err != nil {
		l.Printf("couldn't create writer: %v\n", err)
		return
	}
	var prevTime time.Time
	for i := 0; ; i++ {
		pkt := reader.Next()
		if pkt == nil {
			break
		}
		if *decode {
			pkt.Decode()
			delay := time.Duration(0)
			if i > 0 {
				delay = pkt.Time.Sub(prevTime)
			}
			totalDelay := delay * time.Duration(*delayScale)
			l.Println("sleeping for", totalDelay, "; pkt.Time:", pkt.Time, "; prevTime:", prevTime)
			time.Sleep(totalDelay)
			prevTime = pkt.Time
			l.Println(pkt.String())
		}
		writer.Write(pkt)
		buf.Flush()
	}
}

func main() {
	flag.Parse()

	copyPcap(*output, *input)
}

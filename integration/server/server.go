package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!\n")
	})

	go func() {
		if err := http.ListenAndServe(":80", nil); err != nil {
			log.Printf("HTTP server failed: %v\n", err)
			os.Exit(1)
		}
	}()

	server := http3.Server{
		Addr: ":443",
		QUICConfig: &quic.Config{
			InitialPacketSize: 1200,
			EnableDatagrams:   true,
		},
	}
	if err := server.ListenAndServeTLS("cert.pem", "key.pem"); err != nil {
		log.Printf("HTTP/3 server failed: %v\n", err)
		os.Exit(1)
	}
}

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!\n")
	})

	srv := &http.Server{Addr: ":80"}

	if err := srv.ListenAndServe(); err != nil {
		log.Printf("Server failed: %v\n", err)
		os.Exit(1)
	}
}

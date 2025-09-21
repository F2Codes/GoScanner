package main

import ( "context"
 "encoding/json"
 "encoding/xml"
 "flag"
 "fmt"
 "net"
 "net/url"
 "os"
 "os/exec"
 "path/filepath"
 "regexp"
 "strings"
 "time"
 )

// ---------- ANSI colors ---------- const ( C_RESET  = "\033[0m" C_BOLD   = "\033[1m" C_RED    = "\033[31m" C_GREEN  = "\033[32m" C_YELLOW = "\033[33m" C_BLUE   = "\033[34m" C_CYAN   = "\033[36m" C_MAG    = "\033[35m" )

// ---------- structures to parse Nmap XML and marshal to JSON ---------- type NmapRun struct { XMLName xml.Name xml:"nmaprun" json:"-" Args    string   xml:"args,attr,omitempty" json:"args,omitempty" Started string   xml:"startstr,attr,omitempty" json:"started,omitempty" Hosts   []Host   xml:"host" json:"hosts" }

type Host struct { Addresses []Address xml:"address" json:"addresses" Hostnames Hostnames xml:"hostnames" json:"hostnames,omitempty" Ports     Ports     xml:"ports" json:"ports" Status    Status    xml:"status" json:"status,omitempty" }

type Hostnames struct { Hostname []Hostname xml:"hostname" json:"hostname,omitempty" }

type Hostname struct { Name string xml:"name,attr" json:"name" Type string xml:"type,attr,omitempty" json:"type,omitempty" }

type Status struct { State string xml:"state,attr" json:"state" }

type Address struct { Addr     string xml:"addr,attr" json:"addr" AddrType string xml:"addrtype,attr,omitempty" json:"addrtype,omitempty" }

type Ports struct { Port []Port xml:"port" json:"port,omitempty" }

type Port struct { Protocol string  xml:"protocol,attr" json:"protocol" PortId   string  xml:"portid,attr" json:"port" State    State   xml:"state" json:"state" Service  Service xml:"service" json:"service,omitempty" }

type State struct { State  string xml:"state,attr" json:"state" Reason string xml:"reason,attr,omitempty" json:"reason,omitempty" }

type Service struct { Name    string xml:"name,attr,omitempty" json:"name,omitempty" Product string xml:"product,attr,omitempty" json:"product,omitempty" Version string xml:"version,attr,omitempty" json:"version,omitempty" Extra   string xml:"extrainfo,attr,omitempty" json:"extrainfo,omitempty" }

func main() { // Command-line flags targets := flag.String("targets", "", "target(s). Examples: 192.168.1.1, example.com, https://example.com/path, or multiple separated by commas or spaces") nmapArgs := flag.String("nmap-args", "-sV -p- --open", "extra args for nmap (quote if needed)") timeout := flag.Int("timeout", 300, "timeout for nmap execution in seconds") outDirFlag := flag.String("outdir", "", "output directory (default: ~/storage/shared/Download or current folder)") flag.Parse()

if *targets == "" {
	fmt.Fprintln(os.Stderr, "Error: you must provide at least one target with -targets.")
	os.Exit(1)
}

// normalize and expand targets: accept IPs, hostnames, CIDRs, and URLs
normalized := normalizeTargets(*targets)
if len(normalized) == 0 {
	fmt.Fprintln(os.Stderr, "Error: no valid targets parsed from input.")
	os.Exit(1)
}

// determine output directory
outDir := determineOutDir(*outDirFlag)
if err := os.MkdirAll(outDir, 0755); err != nil {
	fmt.Fprintln(os.Stderr, "Error creating output directory:", err)
	os.Exit(1)
}

// prepare and run nmap for each normalized target (single nmap call with comma-separated targets)
joinedTargets := strings.Join(normalized, ",")
fmt.Printf("%s%s 🚀 Starting scan: %s%s\n", C_BOLD, C_CYAN, joinedTargets, C_RESET)
userArgs := strings.Fields(*nmapArgs)
cmdArgs := append(userArgs, "-oX", "-", joinedTargets) // force XML to stdout for all targets

ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeout)*time.Second)
defer cancel()

cmd := exec.CommandContext(ctx, "nmap", cmdArgs...)
out, err := cmd.Output()
if ctx.Err() == context.DeadlineExceeded {
	fmt.Printf("%s%s⏱️  Error: nmap execution timed out.%s\n", C_BOLD, C_RED, C_RESET)
	os.Exit(2)
}
if err != nil {
	if ee, ok := err.(*exec.ExitError); ok {
		fmt.Fprintf(os.Stderr, "%s%snmap error:%s\n%s\n", C_BOLD, C_RED, C_RESET, string(ee.Stderr))
	} else {
		fmt.Fprintln(os.Stderr, "Error executing nmap:", err)
	}
	os.Exit(1)
}

// filenames use timestamp
now := time.Now().Format("2006-01-02_15-04-05")
xmlPath := filepath.Join(outDir, fmt.Sprintf("scan_%s.xml", now))
jsonPath := filepath.Join(outDir, fmt.Sprintf("scan_%s.json", now))
logPath := filepath.Join(outDir, "Log.txt")

// save raw XML
if err := os.WriteFile(xmlPath, out, 0644); err != nil {
	fmt.Fprintln(os.Stderr, "Error saving XML:", err)
} else {
	fmt.Printf("%s✅ XML saved:%s %s\n", C_GREEN, C_RESET, xmlPath)
}

// parse XML
var nmapRun NmapRun
if err := xml.Unmarshal(out, &nmapRun); err != nil {
	fmt.Fprintln(os.Stderr, "Error parsing XML:", err)
} else {
	if nmapRun.Started == "" {
		nmapRun.Started = now
	}
	// marshal to JSON
	js, err := json.MarshalIndent(nmapRun, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error converting to JSON:", err)
	} else {
		if err := os.WriteFile(jsonPath, js, 0644); err != nil {
			fmt.Fprintln(os.Stderr, "Error saving JSON:", err)
		} else {
			fmt.Printf("%s✅ JSON saved:%s %s\n", C_GREEN, C_RESET, jsonPath)
		}
	}

	// append pretty log (colored output to terminal, plain+emoji to file)
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error opening/writing Log.txt:", err)
	} else {
		defer f.Close()
		pretty := buildPrettyLog(nmapRun, now)
		// print colored version to terminal
		fmt.Print(pretty.Terminal)
		// write plain version (with emojis) to file
		if _, err := f.WriteString(pretty.Plain + "\n\n"); err != nil {
			fmt.Fprintln(os.Stderr, "Error writing log to file:", err)
		} else {
			fmt.Printf("%s📝 Log updated:%s %s\n", C_YELLOW, C_RESET, logPath)
		}
	}
}

fmt.Printf("%s%s Done! 💖%s\n", C_BOLD, C_MAG, C_RESET)

}

// normalizeTargets accepts a string containing comma/space-separated entries that might be // - plain IP addresses or hostnames // - CIDR ranges (expanded by nmap itself if provided) // - full URLs like https://example.com/path // This returns a slice of host:port or host entries that nmap can accept. func normalizeTargets(input string) []string { // split by comma or whitespace re := regexp.MustCompile([,@\s]+) parts := re.Split(strings.TrimSpace(input), -1) out := []string{} for _, p := range parts { if p == "" { continue } // if it looks like a URL, parse and extract host if strings.Contains(p, "://") { u, err := url.Parse(p) if err != nil || u.Host == "" { // try to fallback: maybe missing scheme parsed, err2 := url.Parse("http://" + p) if err2 == nil && parsed.Host != "" { host := stripPort(parsed.Host) out = append(out, host) } continue } host := stripPort(u.Host) if host != "" { out = append(out, host) } continue }

// plain host/ip or CIDR or host:port
	if strings.Contains(p, "/") {
		// CIDR — pass through (nmap will accept)
		out = append(out, p)
		continue
	}

	// if contains scheme-like but without ://, try to parse as host:port
	if strings.Contains(p, ":") {
		// Could be IP:port or hostname:port
		host := stripPort(p)
		if host != "" {
			out = append(out, p) // keep port if present
		}
		continue
	}

	// otherwise assume hostname or ip
	out = append(out, p)
}
// deduplicate while preserving order
seen := map[string]bool{}
uniq := []string{}
for _, v := range out {
	if v == "" {
		continue
	}
	if !seen[v] {
		seen[v] = true
		uniq = append(uniq, v)
	}
}
return uniq

}

func stripPort(hostport string) string { // If host:port, return host part only if h, _, err := net.SplitHostPort(hostport); err == nil { return h } // if SplitHostPort fails, it might be because there's no port — return input return hostport }

// determineOutDir tries ~/storage/shared/Download (Termux) or falls back to current dir func determineOutDir(flagVal string) string { if flagVal != "" { return flagVal } home, err := os.UserHomeDir() if err == nil { possible := filepath.Join(home, "storage", "shared", "Download") if stat, err2 := os.Stat(possible); err2 == nil && stat.IsDir() { return possible } possible2 := filepath.Join(home, "Download") if stat, err3 := os.Stat(possible2); err3 == nil && stat.IsDir() { return possible2 } } cwd, _ := os.Getwd() return cwd }

// PrettyLog holds terminal-colored text and plain text for file type PrettyLog struct { Terminal string Plain    string }

func buildPrettyLog(n NmapRun, timestamp string) PrettyLog { header := fmt.Sprintf("%s%s🔎 NMAP SCAN REPORT — %s%s\n", C_BOLD, C_BLUE, timestamp, C_RESET) plainHeader := fmt.Sprintf("🔎 NMAP SCAN REPORT — %s\n", timestamp)

linesTerm := header
linesPlain := plainHeader

if n.Args != "" {
	linesTerm += fmt.Sprintf("%sArgs:%s %s\n", C_CYAN, C_RESET, n.Args)
	linesPlain += fmt.Sprintf("Args: %s\n", n.Args)
}
linesTerm += fmt.Sprintf("%sHosts found:%s %d\n\n", C_BOLD, C_RESET, len(n.Hosts))
linesPlain += fmt.Sprintf("Hosts found: %d\n\n", len(n.Hosts))

for i, h := range n.Hosts {
	hostLabel := pickHostLabel(h)
	linesTerm += fmt.Sprintf("%s%d) %s%s\n", C_YELLOW, i+1, C_RESET, hostLabel)
	linesPlain += fmt.Sprintf("%d) %s\n", i+1, hostLabel)

	if h.Status.State != "" {
		linesTerm += fmt.Sprintf("   %sStatus:%s %s\n", C_GREEN, C_RESET, h.Status.State)
		linesPlain += fmt.Sprintf("   Status: %s\n", h.Status.State)
	}

	if len(h.Hostnames.Hostname) > 0 {
		names := []string{}
		for _, hn := range h.Hostnames.Hostname {
			names = append(names, hn.Name)
		}
		linesTerm += fmt.Sprintf("   %sHostname(s):%s %s\n", C_MAG, C_RESET, strings.Join(names, ", "))
		linesPlain += fmt.Sprintf("   Hostname(s): %s\n", strings.Join(names, ", "))
	}

	if len(h.Ports.Port) == 0 {
		linesTerm += fmt.Sprintf("   %s⛔ no ports reported%s\n\n", C_RED, C_RESET)
		linesPlain += "   ⛔ no ports reported\n\n"
		continue
	}

	linesTerm += fmt.Sprintf("   %sPorts:%s\n", C_BOLD, C_RESET)
	linesPlain += "   Ports:\n"
	for _, p := range h.Ports.Port {
		info := p.Service.Name
		if p.Service.Product != "" {
			info += " / " + p.Service.Product
		}
		if p.Service.Version != "" {
			info += " " + p.Service.Version
		}
		if info == "" {
			info = "unknown"
		}

		stateEmoji := "🔴"
		stateColor := C_RED
		if strings.ToLower(p.State.State) == "open" {
			stateEmoji = "🟢"
			stateColor = C_GREEN
		} else if strings.ToLower(p.State.State) == "filtered" {
			stateEmoji = "🟡"
			stateColor = C_YELLOW
		}

		linesTerm += fmt.Sprintf("     - %s %s%d/%s%s : %s (%s)\n", stateEmoji, stateColor, atoiSafe(p.PortId), p.Protocol, C_RESET, p.State.State, info)
		linesPlain += fmt.Sprintf("     - %s %s : %s (%s)\n", p.PortId+"/"+p.Protocol, p.State.State, info, stateEmoji)
	}
	linesTerm += "\n"
	linesPlain += "\n"
}

summaryTerm := fmt.Sprintf("%s%s✨ Scan finished at %s — %d hosts — %s%s\n", C_BOLD, C_CYAN, time.Now().Format(time.RFC1123), len(n.Hosts), "Stay legal 😉", C_RESET)
summaryPlain := fmt.Sprintf("✨ Scan finished at %s — %d hosts — Stay legal 😉\n", time.Now().Format(time.RFC1123), len(n.Hosts))

linesTerm += summaryTerm
linesPlain += summaryPlain

return PrettyLog{Terminal: linesTerm, Plain: linesPlain}

}

func pickHostLabel(h Host) string { if len(h.Addresses) > 0 { return h.Addresses[0].Addr } if len(h.Hostnames.Hostname) > 0 { return h.Hostnames.Hostname[0].Name } return "<unknown>" }

func atoiSafe(s string) int { var i int fmt.Sscanf(s, "%d", &i) return i }

flag.Parse()

if *targets == "" {
    fmt.Fprintln(os.Stderr, "Error: you must provide at least one target with -targets.")
    os.Exit(1)
}

// normalize and expand targets
normalized := normalizeTargets(*targets)
if len(normalized) == 0 {
    fmt.Fprintln(os.Stderr, "Error: no valid targets parsed from input.")
    os.Exit(1)
}

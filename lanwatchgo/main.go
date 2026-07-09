package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultConfigPath = "config.json"
	defaultStatePath  = "lanwatchgo-state.json"
)

type Config struct {
	ScanInterval      int      `json:"scan_interval"`
	ExtraSubnets      []string `json:"extra_subnets"`
	StatePath         string   `json:"state_path"`
	PingTimeoutMS     int      `json:"ping_timeout_ms"`
	Concurrency       int      `json:"concurrency"`
	MaxHostsPerSubnet int      `json:"max_hosts_per_subnet"`
}

type TargetSubnet struct {
	CIDR      string
	Network   *net.IPNet
	Interface string
	Source    string
}

type Observation struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac,omitempty"`
	Vendor    string `json:"vendor,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
	Interface string `json:"interface,omitempty"`
	Subnet    string `json:"subnet,omitempty"`
	Key       string `json:"key"`
	KeyType   string `json:"key_type"`
}

type DeviceRecord struct {
	Key        string `json:"key"`
	KeyType    string `json:"key_type"`
	IP         string `json:"ip"`
	MAC        string `json:"mac,omitempty"`
	Vendor     string `json:"vendor,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
	Interface  string `json:"interface,omitempty"`
	Subnet     string `json:"subnet,omitempty"`
	FirstSeen  string `json:"first_seen"`
	LastSeen   string `json:"last_seen"`
	LastStatus string `json:"last_status"`
}

type HistoryEvent struct {
	ScannedAt  string `json:"scanned_at"`
	Key        string `json:"key"`
	KeyType    string `json:"key_type"`
	IP         string `json:"ip"`
	PreviousIP string `json:"previous_ip,omitempty"`
	MAC        string `json:"mac,omitempty"`
	Vendor     string `json:"vendor,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
	Interface  string `json:"interface,omitempty"`
	Subnet     string `json:"subnet,omitempty"`
	Status     string `json:"status"`
}

type State struct {
	Devices map[string]DeviceRecord `json:"devices"`
	History []HistoryEvent          `json:"history"`
}

type ScanReport struct {
	ScannedAt string
	Targets   []TargetSubnet
	New       []DeviceRecord
	ChangedIP []DeviceRecord
	Offline   []DeviceRecord
	Known     []DeviceRecord
}

type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	*s = append(*s, value)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	var err error
	switch os.Args[1] {
	case "scan":
		err = commandScan(os.Args[2:])
	case "watch":
		err = commandWatch(os.Args[2:])
	case "list":
		err = commandList(os.Args[2:])
	case "history":
		err = commandHistory(os.Args[2:])
	case "forget":
		err = commandForget(os.Args[2:])
	case "interfaces":
		err = commandInterfaces(os.Args[2:])
	case "serve":
		err = commandServe(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
	default:
		err = fmt.Errorf("unknown command: %s", os.Args[1])
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func commandScan(args []string) error {
	cfg, err := configFromFlags("scan", args)
	if err != nil {
		return err
	}
	report, err := RunScan(cfg)
	if err != nil {
		return err
	}
	PrintReport(report)
	return nil
}

func commandWatch(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath, "config file path")
	statePath := fs.String("state", "", "state JSON path")
	interval := fs.Int("interval", 0, "scan interval in seconds")
	var extra stringList
	fs.Var(&extra, "subnet", "extra subnet to scan; repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		return err
	}
	applyFlagOverrides(&cfg, *statePath, extra)
	if *interval > 0 {
		cfg.ScanInterval = *interval
	}
	if cfg.ScanInterval <= 0 {
		return errors.New("scan_interval must be greater than zero")
	}

	fmt.Printf("Watching every %d seconds. Press Ctrl+C to stop.\n", cfg.ScanInterval)
	for {
		report, err := RunScan(cfg)
		if err != nil {
			return err
		}
		PrintReport(report)
		time.Sleep(time.Duration(cfg.ScanInterval) * time.Second)
	}
}

func commandList(args []string) error {
	cfg, err := configFromFlags("list", args)
	if err != nil {
		return err
	}
	state, err := LoadState(cfg.StatePath)
	if err != nil {
		return err
	}
	devices := sortedDevices(state.Devices)
	PrintDeviceTable("Known devices", devices)
	return nil
}

func commandHistory(args []string) error {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath, "config file path")
	statePath := fs.String("state", "", "state JSON path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: lanwatchgo history <mac-or-ip>")
	}
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		return err
	}
	applyFlagOverrides(&cfg, *statePath, nil)
	state, err := LoadState(cfg.StatePath)
	if err != nil {
		return err
	}
	PrintHistory(state.History, fs.Arg(0))
	return nil
}

func commandForget(args []string) error {
	fs := flag.NewFlagSet("forget", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath, "config file path")
	statePath := fs.String("state", "", "state JSON path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: lanwatchgo forget <mac-or-ip>")
	}
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		return err
	}
	applyFlagOverrides(&cfg, *statePath, nil)
	state, err := LoadState(cfg.StatePath)
	if err != nil {
		return err
	}

	key := resolveDeviceKey(state, fs.Arg(0))
	if key == "" {
		fmt.Printf("No matching device found: %s\n", fs.Arg(0))
		return nil
	}
	delete(state.Devices, key)
	filtered := state.History[:0]
	for _, event := range state.History {
		if event.Key != key {
			filtered = append(filtered, event)
		}
	}
	state.History = filtered
	if err := SaveState(cfg.StatePath, state); err != nil {
		return err
	}
	fmt.Printf("Forgot device: %s\n", fs.Arg(0))
	return nil
}

func commandInterfaces(args []string) error {
	fs := flag.NewFlagSet("interfaces", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	targets, err := AutoInterfaceSubnets()
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		fmt.Println("No active IPv4 interface subnets detected.")
		return nil
	}
	fmt.Println("Detected interface subnets:")
	for _, target := range targets {
		fmt.Printf("  %-12s %s\n", target.Interface, target.CIDR)
	}
	return nil
}

func commandServe(args []string) error {
	configPath := defaultConfigPath
	statePath := ""
	host := "127.0.0.1"
	port := 5000
	var extra stringList
	var positionals []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-h" || arg == "--help" || arg == "help":
			printServeUsage()
			return nil
		case arg == "-config" || arg == "--config":
			value, next, err := nextArg(args, i, arg)
			if err != nil {
				return err
			}
			configPath = value
			i = next
		case strings.HasPrefix(arg, "-config="):
			configPath = strings.TrimPrefix(arg, "-config=")
		case strings.HasPrefix(arg, "--config="):
			configPath = strings.TrimPrefix(arg, "--config=")
		case arg == "-state" || arg == "--state":
			value, next, err := nextArg(args, i, arg)
			if err != nil {
				return err
			}
			statePath = value
			i = next
		case strings.HasPrefix(arg, "-state="):
			statePath = strings.TrimPrefix(arg, "-state=")
		case strings.HasPrefix(arg, "--state="):
			statePath = strings.TrimPrefix(arg, "--state=")
		case arg == "-host" || arg == "--host":
			value, next, err := nextArg(args, i, arg)
			if err != nil {
				return err
			}
			host = value
			i = next
		case strings.HasPrefix(arg, "-host="):
			host = strings.TrimPrefix(arg, "-host=")
		case strings.HasPrefix(arg, "--host="):
			host = strings.TrimPrefix(arg, "--host=")
		case arg == "-port" || arg == "--port" || arg == "-p":
			value, next, err := nextArg(args, i, arg)
			if err != nil {
				return err
			}
			parsed, err := parsePort(value)
			if err != nil {
				return err
			}
			port = parsed
			i = next
		case strings.HasPrefix(arg, "-port="):
			parsed, err := parsePort(strings.TrimPrefix(arg, "-port="))
			if err != nil {
				return err
			}
			port = parsed
		case strings.HasPrefix(arg, "--port="):
			parsed, err := parsePort(strings.TrimPrefix(arg, "--port="))
			if err != nil {
				return err
			}
			port = parsed
		case strings.HasPrefix(arg, "-p="):
			parsed, err := parsePort(strings.TrimPrefix(arg, "-p="))
			if err != nil {
				return err
			}
			port = parsed
		case arg == "-subnet" || arg == "--subnet":
			value, next, err := nextArg(args, i, arg)
			if err != nil {
				return err
			}
			if err := extra.Set(value); err != nil {
				return err
			}
			i = next
		case strings.HasPrefix(arg, "-subnet="):
			if err := extra.Set(strings.TrimPrefix(arg, "-subnet=")); err != nil {
				return err
			}
		case strings.HasPrefix(arg, "--subnet="):
			if err := extra.Set(strings.TrimPrefix(arg, "--subnet=")); err != nil {
				return err
			}
		case strings.HasPrefix(arg, "-"):
			return fmt.Errorf("unknown serve option %q. Run: lanwatchgo serve --help", arg)
		default:
			positionals = append(positionals, arg)
		}
	}

	if len(positionals) > 2 {
		return fmt.Errorf("too many serve arguments. Run: lanwatchgo serve --help")
	}
	if len(positionals) == 1 {
		if parsed, err := strconv.Atoi(positionals[0]); err == nil {
			port, err = parsePort(strconv.Itoa(parsed))
			if err != nil {
				return err
			}
		} else {
			host = positionals[0]
		}
	}
	if len(positionals) == 2 {
		host = positionals[0]
		parsed, err := parsePort(positionals[1])
		if err != nil {
			return err
		}
		port = parsed
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		return err
	}
	applyFlagOverrides(&cfg, statePath, extra)
	return Serve(cfg, host, port)
}

func configFromFlags(name string, args []string) (Config, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath, "config file path")
	statePath := fs.String("state", "", "state JSON path")
	var extra stringList
	fs.Var(&extra, "subnet", "extra subnet to scan; repeatable")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		return Config{}, err
	}
	applyFlagOverrides(&cfg, *statePath, extra)
	return cfg, nil
}

func applyFlagOverrides(cfg *Config, statePath string, extra stringList) {
	if statePath != "" {
		cfg.StatePath = statePath
	}
	if len(extra) > 0 {
		cfg.ExtraSubnets = append(cfg.ExtraSubnets, extra...)
	}
}

func printUsage() {
	fmt.Println(`LanWatch Go

Usage:
  lanwatchgo scan [--config config.json] [--subnet CIDR]
  lanwatchgo watch [--interval seconds]
  lanwatchgo list
  lanwatchgo history <mac-or-ip>
  lanwatchgo forget <mac-or-ip>
  lanwatchgo interfaces
  lanwatchgo serve
  lanwatchgo serve 5991
  lanwatchgo serve 0.0.0.0 5991
  lanwatchgo serve --host 0.0.0.0 --port 5991

Notes:
  Local interface subnets are detected automatically.
  Use --subnet multiple times or config extra_subnets to add routed networks.
  Brackets in documentation mean optional; do not type [ or ].`)
}

func printServeUsage() {
	fmt.Println(`LanWatch Go serve

Examples:
  lanwatchgo serve
      Runs on http://127.0.0.1:5000

  lanwatchgo serve 5991
      Runs on http://127.0.0.1:5991

  lanwatchgo serve 0.0.0.0 5991
      Runs on http://0.0.0.0:5991

  lanwatchgo serve --host 0.0.0.0 --port 5991
      Same as above, using explicit flags.

Options:
  --host HOST          Host to bind. Default: 127.0.0.1
  --port PORT, -p PORT Port to bind. Default: 5000
  --config PATH        Config file. Default: config.json
  --state PATH         State file override
  --subnet CIDR        Extra subnet; repeatable

Do not type square brackets from examples like [--port 5000]; they only mean optional.`)
}

func nextArg(args []string, index int, name string) (string, int, error) {
	next := index + 1
	if next >= len(args) || strings.HasPrefix(args[next], "-") {
		return "", index, fmt.Errorf("%s requires a value", name)
	}
	return args[next], next, nil
}

func parsePort(value string) (int, error) {
	port, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", value)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port out of range: %d", port)
	}
	return port, nil
}

func DefaultConfig() Config {
	return Config{
		ScanInterval:      60,
		ExtraSubnets:      nil,
		StatePath:         defaultStatePath,
		PingTimeoutMS:     700,
		Concurrency:       128,
		MaxHostsPerSubnet: 4096,
	}
}

func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return cfg, nil
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("read config %s: %w", path, err)
	}
	if cfg.ScanInterval == 0 {
		cfg.ScanInterval = 60
	}
	if cfg.StatePath == "" {
		cfg.StatePath = defaultStatePath
	}
	if cfg.PingTimeoutMS == 0 {
		cfg.PingTimeoutMS = 700
	}
	if cfg.Concurrency == 0 {
		cfg.Concurrency = 128
	}
	if cfg.MaxHostsPerSubnet == 0 {
		cfg.MaxHostsPerSubnet = 4096
	}
	return cfg, nil
}

func RunScan(cfg Config) (ScanReport, error) {
	targets, err := BuildTargets(cfg.ExtraSubnets)
	if err != nil {
		return ScanReport{}, err
	}
	if len(targets) == 0 {
		return ScanReport{}, errors.New("no target subnets detected; add extra_subnets in config")
	}

	arpBefore, _ := ReadARPTable()
	_ = arpBefore
	alive, err := PingSweep(targets, cfg)
	if err != nil {
		return ScanReport{}, err
	}
	arpEntries, err := ReadARPTable()
	if err != nil {
		return ScanReport{}, err
	}
	observations := BuildObservations(targets, alive, arpEntries, time.Duration(cfg.PingTimeoutMS)*time.Millisecond)

	state, err := LoadState(cfg.StatePath)
	if err != nil {
		return ScanReport{}, err
	}
	report := ApplyScan(state, observations, targets)
	if err := SaveState(cfg.StatePath, state); err != nil {
		return ScanReport{}, err
	}
	return report, nil
}

func BuildTargets(extraSubnets []string) ([]TargetSubnet, error) {
	targets, err := AutoInterfaceSubnets()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	merged := make([]TargetSubnet, 0, len(targets)+len(extraSubnets))
	for _, target := range targets {
		if seen[target.CIDR] {
			continue
		}
		seen[target.CIDR] = true
		merged = append(merged, target)
	}

	for _, cidr := range extraSubnets {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid subnet %q: %w", cidr, err)
		}
		network.IP = network.IP.To4()
		if network.IP == nil {
			return nil, fmt.Errorf("only IPv4 subnets are supported: %s", cidr)
		}
		normalized := network.String()
		if seen[normalized] {
			continue
		}
		seen[normalized] = true
		merged = append(merged, TargetSubnet{
			CIDR:    normalized,
			Network: network,
			Source:  "extra",
		})
	}

	sort.Slice(merged, func(i, j int) bool {
		return merged[i].CIDR < merged[j].CIDR
	})
	return merged, nil
}

func AutoInterfaceSubnets() ([]TargetSubnet, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var targets []TargetSubnet
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip, network, ok := ipv4Network(addr)
			if !ok {
				continue
			}
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			targets = append(targets, TargetSubnet{
				CIDR:      network.String(),
				Network:   network,
				Interface: iface.Name,
				Source:    "interface",
			})
		}
	}
	return targets, nil
}

func ipv4Network(addr net.Addr) (net.IP, *net.IPNet, bool) {
	ipNet, ok := addr.(*net.IPNet)
	if !ok {
		return nil, nil, false
	}
	ip := ipNet.IP.To4()
	if ip == nil {
		return nil, nil, false
	}
	networkIP := make(net.IP, len(ip))
	copy(networkIP, ip)
	network := &net.IPNet{IP: networkIP.Mask(ipNet.Mask), Mask: ipNet.Mask}
	return ip, network, true
}

func PingSweep(targets []TargetSubnet, cfg Config) (map[string]bool, error) {
	var ips []net.IP
	for _, target := range targets {
		targetIPs, err := EnumerateHosts(target.Network, cfg.MaxHostsPerSubnet)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", target.CIDR, err)
		}
		ips = append(ips, targetIPs...)
	}
	if len(ips) == 0 {
		return map[string]bool{}, nil
	}

	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 128
	}
	timeout := time.Duration(cfg.PingTimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 700 * time.Millisecond
	}

	jobs := make(chan net.IP)
	results := make(chan string)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				if Ping(ip.String(), timeout) {
					results <- ip.String()
				}
			}
		}()
	}

	go func() {
		for _, ip := range ips {
			jobs <- ip
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	alive := make(map[string]bool)
	for ip := range results {
		alive[ip] = true
	}
	return alive, nil
}

func Ping(ip string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var args []string
	if runtime.GOOS == "windows" {
		args = []string{"-n", "1", "-w", strconv.Itoa(int(timeout / time.Millisecond)), ip}
	} else {
		args = []string{"-c", "1", "-n", ip}
	}
	cmd := exec.CommandContext(ctx, "ping", args...)
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

func EnumerateHosts(network *net.IPNet, maxHosts int) ([]net.IP, error) {
	ones, bits := network.Mask.Size()
	if bits != 32 {
		return nil, errors.New("only IPv4 networks are supported")
	}
	hostCount := uint64(1) << uint(bits-ones)
	if hostCount > uint64(maxHosts) {
		return nil, fmt.Errorf("subnet has %d addresses, above max_hosts_per_subnet=%d", hostCount, maxHosts)
	}

	base := ipToUint32(network.IP)
	mask := binary.BigEndian.Uint32(network.Mask)
	networkAddr := base & mask
	broadcast := networkAddr | ^mask

	start := networkAddr
	end := broadcast
	if hostCount > 2 {
		start = networkAddr + 1
		end = broadcast - 1
	}

	ips := make([]net.IP, 0, int(hostCount))
	for value := start; value <= end; value++ {
		ips = append(ips, uint32ToIP(value))
		if value == ^uint32(0) {
			break
		}
	}
	return ips, nil
}

type ARPEntry struct {
	IP        string
	MAC       string
	Interface string
}

func ReadARPTable() ([]ARPEntry, error) {
	if runtime.GOOS == "linux" {
		if entries, err := readLinuxNeighbors(); err == nil {
			return entries, nil
		}
	}
	return readARPAn()
}

func readLinuxNeighbors() ([]ARPEntry, error) {
	output, err := exec.Command("ip", "neigh", "show").Output()
	if err != nil {
		return nil, err
	}
	var entries []ARPEntry
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		ip := net.ParseIP(fields[0])
		if ip == nil || ip.To4() == nil {
			continue
		}
		entry := ARPEntry{IP: ip.String()}
		for i := 1; i < len(fields)-1; i++ {
			switch fields[i] {
			case "dev":
				entry.Interface = fields[i+1]
			case "lladdr":
				entry.MAC = normalizeMAC(fields[i+1])
			}
		}
		if entry.MAC != "" {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

func readARPAn() ([]ARPEntry, error) {
	output, err := exec.Command("arp", "-an").Output()
	if err != nil {
		return nil, err
	}
	pattern := regexp.MustCompile(`\(([^)]+)\)\s+at\s+([0-9a-fA-F:.-]+|<incomplete>|\(incomplete\))(?:.*\s+on\s+([^\s]+))?`)
	var entries []ARPEntry
	for _, line := range strings.Split(string(output), "\n") {
		match := pattern.FindStringSubmatch(line)
		if len(match) == 0 {
			continue
		}
		ip := net.ParseIP(match[1])
		if ip == nil || ip.To4() == nil {
			continue
		}
		mac := normalizeMAC(match[2])
		if mac == "" {
			continue
		}
		entry := ARPEntry{IP: ip.String(), MAC: mac}
		if len(match) > 3 {
			entry.Interface = match[3]
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func BuildObservations(targets []TargetSubnet, alive map[string]bool, arpEntries []ARPEntry, hostnameTimeout time.Duration) []Observation {
	observations := make(map[string]Observation)

	for ip := range alive {
		target := targetForIP(targets, ip)
		obs := Observation{
			IP:      ip,
			Subnet:  target.CIDR,
			Key:     "ip:" + ip,
			KeyType: "ip",
		}
		observations[ip] = obs
	}

	for _, entry := range arpEntries {
		target := targetForIP(targets, entry.IP)
		if target.CIDR == "" {
			continue
		}
		obs := observations[entry.IP]
		obs.IP = entry.IP
		obs.MAC = entry.MAC
		obs.Vendor = LookupVendor(entry.MAC)
		obs.Interface = entry.Interface
		if obs.Interface == "" {
			obs.Interface = target.Interface
		}
		obs.Subnet = target.CIDR
		obs.Key = entry.MAC
		obs.KeyType = "mac"
		observations[entry.IP] = obs
	}

	result := make([]Observation, 0, len(observations))
	for _, obs := range observations {
		obs.Hostname = ResolveHostname(obs.IP, hostnameTimeout)
		result = append(result, obs)
	}
	sort.Slice(result, func(i, j int) bool {
		return ipToUint32(net.ParseIP(result[i].IP)) < ipToUint32(net.ParseIP(result[j].IP))
	})
	return result
}

func targetForIP(targets []TargetSubnet, ipString string) TargetSubnet {
	ip := net.ParseIP(ipString)
	if ip == nil {
		return TargetSubnet{}
	}
	ip = ip.To4()
	if ip == nil {
		return TargetSubnet{}
	}
	for _, target := range targets {
		if target.Network.Contains(ip) {
			return target
		}
	}
	return TargetSubnet{}
}

func ApplyScan(state *State, observations []Observation, targets []TargetSubnet) ScanReport {
	now := time.Now().UTC().Format(time.RFC3339)
	seen := make(map[string]bool)

	report := ScanReport{
		ScannedAt: now,
		Targets:   targets,
	}

	if state.Devices == nil {
		state.Devices = make(map[string]DeviceRecord)
	}

	for _, obs := range observations {
		key := obs.Key
		if key == "" {
			continue
		}
		seen[key] = true
		existing, exists := state.Devices[key]
		status := "known"
		previousIP := existing.IP

		if !exists {
			status = "new"
			existing.FirstSeen = now
		} else if obs.KeyType == "mac" && existing.IP != "" && existing.IP != obs.IP {
			status = "changed_ip"
		}

		record := DeviceRecord{
			Key:        key,
			KeyType:    obs.KeyType,
			IP:         obs.IP,
			MAC:        obs.MAC,
			Vendor:     coalesce(obs.Vendor, existing.Vendor),
			Hostname:   coalesce(obs.Hostname, existing.Hostname),
			Interface:  coalesce(obs.Interface, existing.Interface),
			Subnet:     coalesce(obs.Subnet, existing.Subnet),
			FirstSeen:  existing.FirstSeen,
			LastSeen:   now,
			LastStatus: status,
		}
		state.Devices[key] = record
		state.History = append(state.History, HistoryEvent{
			ScannedAt:  now,
			Key:        key,
			KeyType:    record.KeyType,
			IP:         record.IP,
			PreviousIP: previousIP,
			MAC:        record.MAC,
			Vendor:     record.Vendor,
			Hostname:   record.Hostname,
			Interface:  record.Interface,
			Subnet:     record.Subnet,
			Status:     status,
		})

		switch status {
		case "new":
			report.New = append(report.New, record)
		case "changed_ip":
			report.ChangedIP = append(report.ChangedIP, record)
		default:
			report.Known = append(report.Known, record)
		}
	}

	for key, existing := range state.Devices {
		if seen[key] || existing.LastStatus == "offline" {
			continue
		}
		existing.LastStatus = "offline"
		state.Devices[key] = existing
		state.History = append(state.History, HistoryEvent{
			ScannedAt:  now,
			Key:        existing.Key,
			KeyType:    existing.KeyType,
			IP:         existing.IP,
			PreviousIP: existing.IP,
			MAC:        existing.MAC,
			Vendor:     existing.Vendor,
			Hostname:   existing.Hostname,
			Interface:  existing.Interface,
			Subnet:     existing.Subnet,
			Status:     "offline",
		})
		report.Offline = append(report.Offline, existing)
	}

	sortReport(&report)
	return report
}

func LoadState(path string) (*State, error) {
	state := &State{Devices: map[string]DeviceRecord{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return state, nil
	}
	if err := json.Unmarshal(data, state); err != nil {
		return nil, fmt.Errorf("read state %s: %w", path, err)
	}
	if state.Devices == nil {
		state.Devices = map[string]DeviceRecord{}
	}
	return state, nil
}

func SaveState(path string, state *State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func PrintReport(report ScanReport) {
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("LanWatch Go Scan")
	fmt.Printf("Scanned: %s\n", report.ScannedAt)
	fmt.Printf("Targets: %s\n", targetLabel(report.Targets))
	fmt.Printf("Active: %d  New: %d  Changed IP: %d  Offline: %d  Known: %d\n",
		len(report.New)+len(report.ChangedIP)+len(report.Known),
		len(report.New),
		len(report.ChangedIP),
		len(report.Offline),
		len(report.Known),
	)
	fmt.Println()
	PrintDeviceTable("New devices", report.New)
	PrintDeviceTable("Changed IP", report.ChangedIP)
	PrintDeviceTable("Offline", report.Offline)
	PrintDeviceTable("Known active", report.Known)
}

func PrintDeviceTable(title string, devices []DeviceRecord) {
	fmt.Println(title)
	if len(devices) == 0 {
		fmt.Println("  none")
		fmt.Println()
		return
	}
	fmt.Printf("  %-12s %-15s %-17s %-10s %-14s %-22s %-22s %s\n", "STATUS", "IP", "MAC", "KEY", "INTERFACE", "FIRST SEEN", "LAST SEEN", "HOSTNAME/VENDOR")
	for _, device := range devices {
		mac := device.MAC
		if mac == "" {
			mac = "-"
		}
		label := strings.TrimSpace(device.Hostname + " " + device.Vendor)
		if label == "" {
			label = "-"
		}
		fmt.Printf("  %-12s %-15s %-17s %-10s %-14s %-22s %-22s %s\n",
			device.LastStatus,
			device.IP,
			mac,
			device.KeyType,
			emptyDash(device.Interface),
			device.FirstSeen,
			device.LastSeen,
			label,
		)
	}
	fmt.Println()
}

func PrintHistory(history []HistoryEvent, identifier string) {
	keyIdentifier := normalizeMAC(identifier)
	fmt.Println("History")
	fmt.Printf("  %-22s %-12s %-15s %-17s %-15s %s\n", "SCANNED", "STATUS", "IP", "MAC", "PREVIOUS IP", "HOSTNAME/VENDOR")
	found := false
	for i := len(history) - 1; i >= 0; i-- {
		event := history[i]
		if !historyMatches(event, identifier, keyIdentifier) {
			continue
		}
		found = true
		label := strings.TrimSpace(event.Hostname + " " + event.Vendor)
		if label == "" {
			label = "-"
		}
		fmt.Printf("  %-22s %-12s %-15s %-17s %-15s %s\n",
			event.ScannedAt,
			event.Status,
			event.IP,
			emptyDash(event.MAC),
			emptyDash(event.PreviousIP),
			label,
		)
	}
	if !found {
		fmt.Println("  no history found")
	}
}

func Serve(cfg Config, host string, port int) error {
	var mu sync.Mutex
	var lastReport *ScanReport
	var lastError string

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		state, _ := LoadState(cfg.StatePath)
		query := r.URL.Query().Get("history")
		devices := sortedDevices(state.Devices)
		active := filterDevices(devices, func(device DeviceRecord) bool {
			return device.LastStatus != "offline"
		})
		changed := filterDevices(devices, func(device DeviceRecord) bool {
			return device.LastStatus == "changed_ip"
		})
		offline := filterDevices(devices, func(device DeviceRecord) bool {
			return device.LastStatus == "offline"
		})
		history := recentHistory(state.History, query, 30)
		newRecent := recentNewDevices(state, 10*time.Minute)
		mu.Lock()
		report := lastReport
		errText := lastError
		mu.Unlock()
		data := dashboardData{
			Config:       cfg,
			Report:       report,
			Error:        errText,
			Devices:      devices,
			Active:       active,
			Changed:      changed,
			Offline:      offline,
			NewRecent:    newRecent,
			History:      history,
			HistoryQuery: query,
			SubnetGroups: buildSubnetGroups(devices),
		}
		if err := dashboardTemplate.Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		report, err := RunScan(cfg)
		mu.Lock()
		if err != nil {
			lastError = err.Error()
		} else {
			lastReport = &report
			lastError = ""
		}
		mu.Unlock()
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	address := fmt.Sprintf("%s:%d", host, port)
	fmt.Printf("LanWatch Go dashboard: http://%s\n", address)
	return http.ListenAndServe(address, mux)
}

type dashboardData struct {
	Config       Config
	Report       *ScanReport
	Error        string
	Devices      []DeviceRecord
	Active       []DeviceRecord
	Changed      []DeviceRecord
	Offline      []DeviceRecord
	NewRecent    []DeviceRecord
	History      []HistoryEvent
	HistoryQuery string
	SubnetGroups []SubnetDeviceGroup
}

type SubnetDeviceGroup struct {
	Name    string
	Devices []DeviceRecord
}

var dashboardTemplate = template.Must(template.New("dashboard").Funcs(template.FuncMap{
	"dict": func(values ...interface{}) map[string]interface{} {
		dict := make(map[string]interface{}, len(values)/2)
		for i := 0; i+1 < len(values); i += 2 {
			key, _ := values[i].(string)
			dict[key] = values[i+1]
		}
		return dict
	},
	"targetLabel": func(report *ScanReport) string {
		if report == nil {
			return "not scanned yet"
		}
		return targetLabel(report.Targets)
	},
	"statusClass": func(status string) string {
		return strings.ReplaceAll(status, "_", "-")
	},
	"dash": emptyDash,
}).Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>LanWatch Go</title>
  <style>
    body { margin: 0; background: #f5f7fa; color: #1d2733; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; font-size: 14px; }
    header { background: #102033; color: #f8fafc; padding: 18px 24px; }
    main { padding: 20px 24px 36px; }
    h1 { margin: 0; font-size: 22px; }
    h2 { font-size: 15px; margin: 22px 0 10px; }
    .meta { color: #cbd5e1; margin-top: 4px; }
    .bar { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
    button, .button { background: #0f766e; border: 1px solid #115e59; color: white; border-radius: 6px; padding: 8px 14px; font-weight: 700; cursor: pointer; text-decoration: none; }
    input { border: 1px solid #d9e1ea; border-radius: 6px; padding: 8px 10px; min-width: 260px; }
    .notice { background: #fff7ed; border: 1px solid #fed7aa; color: #7c2d12; border-radius: 8px; padding: 10px 12px; margin-bottom: 16px; }
    .summary { display: grid; grid-template-columns: repeat(5, minmax(120px, 1fr)); gap: 10px; margin: 18px 0 22px; }
    .metric { background: white; border: 1px solid #d9e1ea; border-radius: 8px; padding: 12px; }
    .metric span { display: block; color: #657487; font-size: 12px; text-transform: uppercase; }
    .metric strong { display: block; font-size: 28px; margin-top: 5px; }
    .split { display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(320px, .8fr); gap: 18px; align-items: start; }
    .table-wrap { overflow-x: auto; background: white; border: 1px solid #d9e1ea; border-radius: 8px; }
    table { width: 100%; border-collapse: collapse; min-width: 780px; }
    th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid #d9e1ea; white-space: nowrap; }
    th { background: #eef3f8; font-size: 12px; text-transform: uppercase; color: #334155; }
    tr:last-child td { border-bottom: 0; }
    code { background: #eef3f8; border: 1px solid #d9e1ea; border-radius: 5px; padding: 2px 5px; }
    .empty { background: white; border: 1px solid #d9e1ea; border-radius: 8px; padding: 16px; color: #657487; }
    .status { border-radius: 999px; padding: 3px 8px; font-size: 12px; font-weight: 700; display: inline-block; }
    .new { background: #dcfce7; color: #166534; }
    .known { background: #e0f2fe; color: #075985; }
    .changed-ip { background: #fef3c7; color: #b45309; }
    .offline { background: #fee2e2; color: #b91c1c; }
    @media (max-width: 860px) { .summary, .split { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <header>
    <div class="bar">
      <div>
        <h1>LanWatch Go</h1>
        <div class="meta">{{ targetLabel .Report }} · state {{ .Config.StatePath }}</div>
      </div>
      <form method="post" action="/scan"><button type="submit">Run Scan</button></form>
    </div>
  </header>
  <main>
    {{ if .Error }}<div class="notice">{{ .Error }}</div>{{ end }}
    <div class="bar">
      <a class="button" href="/">Refresh</a>
      <form method="get" action="/">
        <input name="history" value="{{ .HistoryQuery }}" placeholder="MAC or IP history">
        <button type="submit">History</button>
      </form>
    </div>
    <div class="summary">
      <div class="metric"><span>New</span><strong>{{ if .Report }}{{ len .Report.New }}{{ else }}0{{ end }}</strong></div>
      <div class="metric"><span>Changed IP</span><strong>{{ if .Report }}{{ len .Report.ChangedIP }}{{ else }}0{{ end }}</strong></div>
      <div class="metric"><span>Offline</span><strong>{{ if .Report }}{{ len .Report.Offline }}{{ else }}0{{ end }}</strong></div>
      <div class="metric"><span>Known</span><strong>{{ if .Report }}{{ len .Report.Known }}{{ else }}0{{ end }}</strong></div>
      <div class="metric"><span>Total</span><strong>{{ len .Devices }}</strong></div>
    </div>
    <div class="split">
      <div>
        {{ if .Report }}
          {{ template "devices" dict "Title" "New devices" "Rows" .Report.New }}
          {{ template "devices" dict "Title" "Changed IP" "Rows" .Report.ChangedIP }}
          {{ template "devices" dict "Title" "Offline" "Rows" .Report.Offline }}
          {{ template "devices" dict "Title" "Known active" "Rows" .Report.Known }}
        {{ end }}
        {{ template "devices" dict "Title" "All known devices" "Rows" .Devices }}
      </div>
      <div>
        {{ template "history" .History }}
      </div>
    </div>
  </main>
</body>
</html>

{{ define "devices" }}
<section>
  <h2>{{ .Title }}</h2>
  {{ if .Rows }}
  <div class="table-wrap"><table>
    <thead><tr><th>Status</th><th>IP</th><th>MAC</th><th>Key</th><th>Interface</th><th>Hostname</th><th>Vendor</th><th>Last Seen</th></tr></thead>
    <tbody>
      {{ range .Rows }}
      <tr>
        <td><span class="status {{ statusClass .LastStatus }}">{{ .LastStatus }}</span></td>
        <td>{{ .IP }}</td>
        <td>{{ dash .MAC }}</td>
        <td>{{ .KeyType }}</td>
        <td>{{ dash .Interface }}</td>
        <td>{{ dash .Hostname }}</td>
        <td>{{ dash .Vendor }}</td>
        <td>{{ .LastSeen }}</td>
      </tr>
      {{ end }}
    </tbody>
  </table></div>
  {{ else }}
  <div class="empty">None</div>
  {{ end }}
</section>
{{ end }}

{{ define "history" }}
<section>
  <h2>History</h2>
  {{ if . }}
  <div class="table-wrap"><table>
    <thead><tr><th>Scanned</th><th>Status</th><th>IP</th><th>MAC</th><th>Previous IP</th><th>Hostname</th></tr></thead>
    <tbody>
      {{ range . }}
      <tr>
        <td>{{ .ScannedAt }}</td>
        <td><span class="status {{ statusClass .Status }}">{{ .Status }}</span></td>
        <td>{{ .IP }}</td>
        <td>{{ dash .MAC }}</td>
        <td>{{ dash .PreviousIP }}</td>
        <td>{{ dash .Hostname }}</td>
      </tr>
      {{ end }}
    </tbody>
  </table></div>
  {{ else }}
  <div class="empty">No history found.</div>
  {{ end }}
</section>
{{ end }}
`))

func recentHistory(history []HistoryEvent, query string, limit int) []HistoryEvent {
	var rows []HistoryEvent
	keyQuery := normalizeMAC(query)
	for i := len(history) - 1; i >= 0 && len(rows) < limit; i-- {
		event := history[i]
		if query != "" && !historyMatches(event, query, keyQuery) {
			continue
		}
		rows = append(rows, event)
	}
	return rows
}

func historyMatches(event HistoryEvent, identifier, normalizedMAC string) bool {
	if identifier == "" {
		return true
	}
	return event.Key == identifier ||
		event.Key == "ip:"+identifier ||
		event.IP == identifier ||
		event.PreviousIP == identifier ||
		(normalizedMAC != "" && event.MAC == normalizedMAC)
}

func sortedDevices(devices map[string]DeviceRecord) []DeviceRecord {
	rows := make([]DeviceRecord, 0, len(devices))
	for _, device := range devices {
		rows = append(rows, device)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].LastSeen == rows[j].LastSeen {
			return rows[i].Key < rows[j].Key
		}
		return rows[i].LastSeen > rows[j].LastSeen
	})
	return rows
}

func sortReport(report *ScanReport) {
	sortDevices := func(rows []DeviceRecord) {
		sort.Slice(rows, func(i, j int) bool {
			return ipToUint32(net.ParseIP(rows[i].IP)) < ipToUint32(net.ParseIP(rows[j].IP))
		})
	}
	sortDevices(report.New)
	sortDevices(report.ChangedIP)
	sortDevices(report.Offline)
	sortDevices(report.Known)
}

func resolveDeviceKey(state *State, identifier string) string {
	normalizedMAC := normalizeMAC(identifier)
	for key, device := range state.Devices {
		if key == identifier || key == "ip:"+identifier || device.IP == identifier || (normalizedMAC != "" && device.MAC == normalizedMAC) {
			return key
		}
	}
	return ""
}

func targetLabel(targets []TargetSubnet) string {
	if len(targets) == 0 {
		return "-"
	}
	labels := make([]string, 0, len(targets))
	for _, target := range targets {
		if target.Interface != "" {
			labels = append(labels, target.CIDR+" on "+target.Interface)
		} else {
			labels = append(labels, target.CIDR)
		}
	}
	return strings.Join(labels, ", ")
}

func ResolveHostname(ip string, timeout time.Duration) string {
	type result struct {
		names []string
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		names, err := net.LookupAddr(ip)
		ch <- result{names: names, err: err}
	}()
	select {
	case res := <-ch:
		if res.err != nil || len(res.names) == 0 {
			return ""
		}
		return strings.TrimSuffix(res.names[0], ".")
	case <-time.After(timeout):
		return ""
	}
}

func LookupVendor(mac string) string {
	oui := OUI(mac)
	if oui == "" {
		return ""
	}
	return fallbackVendors[oui]
}

func OUI(mac string) string {
	normalized := normalizeMAC(mac)
	if normalized == "" {
		return ""
	}
	parts := strings.Split(normalized, ":")
	if len(parts) < 3 {
		return ""
	}
	return strings.Join(parts[:3], ":")
}

var fallbackVendors = map[string]string{
	"00:00:0c": "Cisco Systems",
	"00:03:93": "Apple",
	"00:05:02": "Apple",
	"00:0a:95": "Apple",
	"00:14:22": "Dell",
	"00:50:56": "VMware",
	"00:e0:4c": "Realtek",
	"08:00:27": "Oracle VirtualBox",
	"3c:5a:b4": "Google",
	"44:65:0d": "Amazon",
	"50:c7:bf": "TP-Link",
	"60:01:94": "Espressif",
	"64:16:66": "Nest Labs",
	"74:e2:8c": "Microsoft",
	"b8:27:eb": "Raspberry Pi",
	"d8:3a:dd": "Raspberry Pi",
	"dc:a6:32": "Raspberry Pi",
}

func normalizeMAC(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.Trim(value, "<>()")
	value = strings.ReplaceAll(value, "-", ":")
	value = strings.ReplaceAll(value, ".", "")
	if value == "" || strings.Contains(value, "incomplete") {
		return ""
	}
	if !strings.Contains(value, ":") && len(value) == 12 {
		parts := make([]string, 0, 6)
		for i := 0; i < 12; i += 2 {
			parts = append(parts, value[i:i+2])
		}
		value = strings.Join(parts, ":")
	}
	parts := strings.Split(value, ":")
	if len(parts) != 6 {
		return ""
	}
	normalized := make([]string, 0, 6)
	for _, part := range parts {
		if part == "" || len(part) > 2 {
			return ""
		}
		parsed, err := strconv.ParseUint(part, 16, 8)
		if err != nil {
			return ""
		}
		normalized = append(normalized, fmt.Sprintf("%02x", parsed))
	}
	return strings.Join(normalized, ":")
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP(value uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, value)
	return ip
}

func coalesce(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func emptyDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

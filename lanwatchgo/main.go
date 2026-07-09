package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
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
	Interfaces        []string `json:"interfaces"`
	ExcludeInterfaces []string `json:"exclude_interfaces"`
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
	Devices           map[string]DeviceRecord `json:"devices"`
	History           []HistoryEvent          `json:"history"`
	NewArchivedBefore string                  `json:"new_archived_before,omitempty"`
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
	case "baseline":
		err = commandBaseline(os.Args[2:])
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

func commandBaseline(args []string) error {
	cfg, err := configFromFlags("baseline", args)
	if err != nil {
		return err
	}
	report, err := RunBaseline(cfg)
	if err != nil {
		return err
	}
	fmt.Printf("Baseline saved: %d active devices recorded as known.\n", len(report.Known))
	PrintReport(report)
	return nil
}

func commandWatch(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath, "config file path")
	statePath := fs.String("state", "", "state JSON path")
	interval := fs.Int("interval", 0, "scan interval in seconds")
	var extra stringList
	var interfaces stringList
	var excludeInterfaces stringList
	fs.Var(&extra, "subnet", "extra subnet to scan; repeatable")
	fs.Var(&interfaces, "interface", "interface to include; repeatable")
	fs.Var(&excludeInterfaces, "exclude-interface", "interface to exclude; repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := applyScanPositionals(fs.Args(), &interfaces); err != nil {
		return err
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		return err
	}
	applyFlagOverrides(&cfg, *statePath, extra, interfaces, excludeInterfaces)
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
	applyFlagOverrides(&cfg, *statePath, nil, nil, nil)
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
	applyFlagOverrides(&cfg, *statePath, nil, nil, nil)
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
	var interfaces stringList
	var excludeInterfaces stringList
	fs.Var(&interfaces, "interface", "interface to include; repeatable")
	fs.Var(&excludeInterfaces, "exclude-interface", "interface to exclude; repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	targets, err := AutoInterfaceSubnets(interfaces, excludeInterfaces)
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
	var interfaces stringList
	var excludeInterfaces stringList
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
		case arg == "-interface" || arg == "--interface":
			value, next, err := nextArg(args, i, arg)
			if err != nil {
				return err
			}
			if err := interfaces.Set(value); err != nil {
				return err
			}
			i = next
		case strings.HasPrefix(arg, "-interface="):
			if err := interfaces.Set(strings.TrimPrefix(arg, "-interface=")); err != nil {
				return err
			}
		case strings.HasPrefix(arg, "--interface="):
			if err := interfaces.Set(strings.TrimPrefix(arg, "--interface=")); err != nil {
				return err
			}
		case arg == "-exclude-interface" || arg == "--exclude-interface":
			value, next, err := nextArg(args, i, arg)
			if err != nil {
				return err
			}
			if err := excludeInterfaces.Set(value); err != nil {
				return err
			}
			i = next
		case strings.HasPrefix(arg, "-exclude-interface="):
			if err := excludeInterfaces.Set(strings.TrimPrefix(arg, "-exclude-interface=")); err != nil {
				return err
			}
		case strings.HasPrefix(arg, "--exclude-interface="):
			if err := excludeInterfaces.Set(strings.TrimPrefix(arg, "--exclude-interface=")); err != nil {
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
	applyFlagOverrides(&cfg, statePath, extra, interfaces, excludeInterfaces)
	return Serve(cfg, host, port)
}

func configFromFlags(name string, args []string) (Config, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath, "config file path")
	statePath := fs.String("state", "", "state JSON path")
	var extra stringList
	var interfaces stringList
	var excludeInterfaces stringList
	fs.Var(&extra, "subnet", "extra subnet to scan; repeatable")
	fs.Var(&interfaces, "interface", "interface to include; repeatable")
	fs.Var(&excludeInterfaces, "exclude-interface", "interface to exclude; repeatable")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if err := applyScanPositionals(fs.Args(), &interfaces); err != nil {
		return Config{}, err
	}
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		return Config{}, err
	}
	applyFlagOverrides(&cfg, *statePath, extra, interfaces, excludeInterfaces)
	return cfg, nil
}

func applyFlagOverrides(cfg *Config, statePath string, extra, interfaces, excludeInterfaces stringList) {
	if statePath != "" {
		cfg.StatePath = statePath
	}
	if len(extra) > 0 {
		cfg.ExtraSubnets = append(cfg.ExtraSubnets, extra...)
	}
	if len(interfaces) > 0 {
		cfg.Interfaces = append(cfg.Interfaces, interfaces...)
	}
	if len(excludeInterfaces) > 0 {
		cfg.ExcludeInterfaces = append(cfg.ExcludeInterfaces, excludeInterfaces...)
	}
}

func applyScanPositionals(args []string, interfaces *stringList) error {
	if len(args) == 0 {
		return nil
	}
	if args[0] == "interface" || args[0] == "interfaces" {
		if len(args) == 1 {
			return errors.New("usage: lanwatchgo scan --interface enp0s3")
		}
		for _, name := range args[1:] {
			if err := interfaces.Set(name); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("unexpected arguments: %s. Use --interface enp0s3, --subnet CIDR, or run 'lanwatchgo help'", strings.Join(args, " "))
}

func printUsage() {
	fmt.Println(`LanWatch Go

Usage:
  lanwatchgo baseline [--config config.json] [--interface NAME] [--subnet CIDR]
  lanwatchgo scan [--config config.json] [--interface NAME] [--subnet CIDR]
  lanwatchgo watch [--interval seconds]
  lanwatchgo list
  lanwatchgo history <mac-or-ip>
  lanwatchgo forget <mac-or-ip>
  lanwatchgo interfaces [--interface NAME]
  lanwatchgo serve
  lanwatchgo serve 5991
  lanwatchgo serve 0.0.0.0 5991
  lanwatchgo serve --host 0.0.0.0 --port 5991

Notes:
  Run baseline once to record current devices as known before watching for new devices.
  Local interface subnets are detected automatically.
  Interfaces that are down or have no carrier/running state are skipped.
  Use --subnet multiple times or config extra_subnets to add routed networks.
  Use --interface enp0s3 to scan only one interface.
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
  --interface NAME     Interface to include; repeatable
  --exclude-interface NAME
                       Interface to exclude; repeatable

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
	if cfg.ScanInterval <= 0 {
		cfg.ScanInterval = 60
	}
	if cfg.StatePath == "" {
		cfg.StatePath = defaultStatePath
	}
	if cfg.PingTimeoutMS <= 0 {
		cfg.PingTimeoutMS = 700
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 128
	}
	if cfg.MaxHostsPerSubnet <= 0 {
		cfg.MaxHostsPerSubnet = 4096
	}
	return cfg, nil
}

func RunScan(cfg Config) (ScanReport, error) {
	started := time.Now()
	log.Printf("scan: starting state=%s interfaces=%s extra_subnets=%s", cfg.StatePath, strings.Join(cfg.Interfaces, ","), strings.Join(cfg.ExtraSubnets, ","))
	observations, targets, err := Discover(cfg)
	if err != nil {
		log.Printf("scan: failed during discovery: %v", err)
		return ScanReport{}, err
	}
	state, err := LoadState(cfg.StatePath)
	if err != nil {
		log.Printf("scan: failed loading state: %v", err)
		return ScanReport{}, err
	}
	report := ApplyScan(state, observations, targets)
	if err := SaveState(cfg.StatePath, state); err != nil {
		log.Printf("scan: failed saving state: %v", err)
		return ScanReport{}, err
	}
	log.Printf("scan: complete duration=%s %s", time.Since(started).Round(time.Millisecond), reportLogSummary(report))
	return report, nil
}

func RunBaseline(cfg Config) (ScanReport, error) {
	started := time.Now()
	log.Printf("baseline: starting state=%s interfaces=%s extra_subnets=%s", cfg.StatePath, strings.Join(cfg.Interfaces, ","), strings.Join(cfg.ExtraSubnets, ","))
	observations, targets, err := Discover(cfg)
	if err != nil {
		log.Printf("baseline: failed during discovery: %v", err)
		return ScanReport{}, err
	}
	state, err := LoadState(cfg.StatePath)
	if err != nil {
		log.Printf("baseline: failed loading state: %v", err)
		return ScanReport{}, err
	}
	report := ApplyBaseline(state, observations, targets)
	if err := SaveState(cfg.StatePath, state); err != nil {
		log.Printf("baseline: failed saving state: %v", err)
		return ScanReport{}, err
	}
	log.Printf("baseline: complete duration=%s known=%d offline=%d targets=%s", time.Since(started).Round(time.Millisecond), len(report.Known), len(report.Offline), targetLabel(report.Targets))
	return report, nil
}

func Discover(cfg Config) ([]Observation, []TargetSubnet, error) {
	started := time.Now()
	targets, err := BuildTargets(cfg)
	if err != nil {
		return nil, nil, err
	}
	if len(targets) == 0 {
		return nil, nil, errors.New("no target subnets detected; add extra_subnets in config")
	}
	log.Printf("discover: targets=%s", targetLabel(targets))

	alive, err := PingSweep(targets, cfg)
	if err != nil {
		return nil, nil, err
	}
	log.Printf("discover: ping sweep alive=%d", len(alive))
	arpEntries, err := ReadARPTable()
	if err != nil {
		return nil, nil, err
	}
	log.Printf("discover: arp/neigh entries=%d", len(arpEntries))
	observations := BuildObservations(targets, alive, arpEntries, time.Duration(cfg.PingTimeoutMS)*time.Millisecond)
	log.Printf("discover: observations=%d duration=%s", len(observations), time.Since(started).Round(time.Millisecond))
	return observations, targets, nil
}

func BuildTargets(cfg Config) ([]TargetSubnet, error) {
	targets, err := AutoInterfaceSubnets(cfg.Interfaces, cfg.ExcludeInterfaces)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	merged := make([]TargetSubnet, 0, len(targets)+len(cfg.ExtraSubnets))
	for _, target := range targets {
		if seen[target.CIDR] {
			continue
		}
		addressCount := subnetAddressCount(target.Network)
		if addressCount > uint64(cfg.MaxHostsPerSubnet) {
			fmt.Fprintf(
				os.Stderr,
				"warning: skipping %s on %s: subnet has %d addresses, above max_hosts_per_subnet=%d\n",
				target.CIDR,
				target.Interface,
				addressCount,
				cfg.MaxHostsPerSubnet,
			)
			continue
		}
		seen[target.CIDR] = true
		merged = append(merged, target)
	}

	for _, cidr := range cfg.ExtraSubnets {
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
		addressCount := subnetAddressCount(network)
		if addressCount > uint64(cfg.MaxHostsPerSubnet) {
			return nil, fmt.Errorf(
				"%s: subnet has %d addresses, above max_hosts_per_subnet=%d",
				normalized,
				addressCount,
				cfg.MaxHostsPerSubnet,
			)
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

func AutoInterfaceSubnets(includeInterfaces, excludeInterfaces []string) ([]TargetSubnet, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	include := stringSet(includeInterfaces)
	exclude := stringSet(excludeInterfaces)
	var targets []TargetSubnet
	for _, iface := range interfaces {
		if len(include) > 0 && !include[iface.Name] {
			continue
		}
		if exclude[iface.Name] {
			continue
		}
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagRunning == 0 {
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
	log.Printf("ping: scanning ips=%d concurrency=%d timeout=%s", len(ips), concurrency, timeout)

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
	_, bits := network.Mask.Size()
	if bits != 32 {
		return nil, errors.New("only IPv4 networks are supported")
	}
	hostCount := subnetAddressCount(network)
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

func subnetAddressCount(network *net.IPNet) uint64 {
	ones, bits := network.Mask.Size()
	if bits != 32 || ones < 0 {
		return 0
	}
	return uint64(1) << uint(bits-ones)
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

func ApplyBaseline(state *State, observations []Observation, targets []TargetSubnet) ScanReport {
	now := time.Now().UTC().Format(time.RFC3339)
	seen := make(map[string]bool)

	report := ScanReport{
		ScannedAt: now,
		Targets:   targets,
	}

	if state.Devices == nil {
		state.Devices = make(map[string]DeviceRecord)
	}
	state.NewArchivedBefore = now

	for _, obs := range observations {
		key := obs.Key
		if key == "" {
			continue
		}
		seen[key] = true
		existing := state.Devices[key]
		firstSeen := existing.FirstSeen
		if firstSeen == "" {
			firstSeen = now
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
			FirstSeen:  firstSeen,
			LastSeen:   now,
			LastStatus: "known",
		}
		state.Devices[key] = record
		state.History = append(state.History, HistoryEvent{
			ScannedAt:  now,
			Key:        key,
			KeyType:    record.KeyType,
			IP:         record.IP,
			PreviousIP: existing.IP,
			MAC:        record.MAC,
			Vendor:     record.Vendor,
			Hostname:   record.Hostname,
			Interface:  record.Interface,
			Subnet:     record.Subnet,
			Status:     "known",
		})
		report.Known = append(report.Known, record)
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
	var scanMu sync.Mutex
	var autoMu sync.Mutex
	var autoRunning bool
	var autoInterval = 10
	var autoStop chan struct{}

	runAndStoreScan := func() {
		scanMu.Lock()
		defer scanMu.Unlock()

		log.Printf("server: scan requested")
		report, err := RunScan(cfg)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			lastError = err.Error()
			log.Printf("server: scan failed: %v", err)
			return
		}
		lastReport = &report
		lastError = ""
		log.Printf("server: scan stored %s", reportLogSummary(report))
	}

	stopAutoScan := func() {
		autoMu.Lock()
		defer autoMu.Unlock()
		if autoRunning && autoStop != nil {
			close(autoStop)
			log.Printf("autoscan: stopped")
		}
		autoRunning = false
		autoStop = nil
	}

	startAutoScan := func(interval int) {
		if interval <= 0 {
			interval = 10
		}

		autoMu.Lock()
		if autoRunning && autoStop != nil {
			close(autoStop)
		}
		stop := make(chan struct{})
		autoStop = stop
		autoRunning = true
		autoInterval = interval
		autoMu.Unlock()
		log.Printf("autoscan: started interval=%ds", interval)

		go func() {
			runAndStoreScan()
			ticker := time.NewTicker(time.Duration(interval) * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					log.Printf("autoscan: tick")
					runAndStoreScan()
				case <-stop:
					return
				}
			}
		}()
	}

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
		autoMu.Lock()
		running := autoRunning
		interval := autoInterval
		autoMu.Unlock()
		data := dashboardData{
			Config:       cfg,
			Report:       report,
			Error:        errText,
			AutoRunning:  running,
			AutoInterval: interval,
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
		log.Printf("http: run scan button clicked")
		runAndStoreScan()
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
	mux.HandleFunc("/archive-new", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		state, err := LoadState(cfg.StatePath)
		if err == nil {
			state.NewArchivedBefore = time.Now().UTC().Format(time.RFC3339)
			err = SaveState(cfg.StatePath, state)
		}
		mu.Lock()
		if err != nil {
			lastError = err.Error()
		} else {
			lastError = ""
			log.Printf("archive: current new devices archived before=%s", state.NewArchivedBefore)
		}
		mu.Unlock()
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
	mux.HandleFunc("/autoscan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		switch r.FormValue("action") {
		case "stop":
			stopAutoScan()
		default:
			interval, err := strconv.Atoi(r.FormValue("interval"))
			if err != nil || interval <= 0 {
				interval = 10
			}
			startAutoScan(interval)
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	address := fmt.Sprintf("%s:%d", host, port)
	log.Printf("server: starting dashboard http://%s state=%s interfaces=%s extra_subnets=%s", address, cfg.StatePath, strings.Join(cfg.Interfaces, ","), strings.Join(cfg.ExtraSubnets, ","))
	return http.ListenAndServe(address, mux)
}

type dashboardData struct {
	Config       Config
	Report       *ScanReport
	Error        string
	AutoRunning  bool
	AutoInterval int
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
	"tabID": tabID,
	"dash":  emptyDash,
}).Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>LanWatch Go</title>
  <style>
    :root {
      --bg: #f5f7fa;
      --panel: #ffffff;
      --text: #1d2733;
      --muted: #657487;
      --line: #d9e1ea;
      --head: #102033;
      --accent: #0f766e;
      --accent-strong: #115e59;
      --warn: #b45309;
      --danger: #b91c1c;
      --ok: #166534;
    }
    * { box-sizing: border-box; }
    body { margin: 0; background: var(--bg); color: var(--text); font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; font-size: 14px; }
    header { background: var(--head); color: #f8fafc; padding: 18px 24px; }
    main { padding: 20px 24px 36px; }
    h1 { margin: 0; font-size: 22px; }
    h2 { font-size: 15px; margin: 0 0 10px; }
    .meta { color: #cbd5e1; margin-top: 4px; }
    .bar { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
    button, .button { min-height: 36px; background: var(--accent); border: 1px solid var(--accent-strong); color: white; border-radius: 6px; padding: 8px 14px; font-weight: 700; cursor: pointer; text-decoration: none; }
    input { min-height: 36px; border: 1px solid var(--line); border-radius: 6px; padding: 8px 10px; min-width: 260px; }
    .notice { background: #fff7ed; border: 1px solid #fed7aa; color: #7c2d12; border-radius: 8px; padding: 10px 12px; margin-bottom: 16px; }
    .summary { display: grid; grid-template-columns: repeat(5, minmax(120px, 1fr)); gap: 10px; margin: 18px 0 22px; }
    .metric { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 12px; min-height: 76px; }
    .metric span { display: block; color: var(--muted); font-size: 12px; text-transform: uppercase; }
    .metric strong { display: block; font-size: 28px; margin-top: 5px; line-height: 1; }
    .highlight { margin-bottom: 18px; }
    .device-tabs { margin-top: 18px; }
    .device-tabs-head { display: flex; align-items: flex-end; justify-content: space-between; gap: 10px; margin-bottom: 8px; }
    .device-tabs-head .subtle { color: var(--muted); font-size: 12px; }
    .section-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 10px; }
    .inline-form { display: inline-flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .inline-form input[type="number"] { width: 88px; min-width: 88px; }
    .table-wrap { overflow-x: auto; background: var(--panel); border: 1px solid var(--line); border-radius: 8px; }
    table { width: 100%; border-collapse: collapse; min-width: 860px; }
    th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--line); white-space: nowrap; }
    th { background: #eef3f8; font-size: 12px; text-transform: uppercase; color: #334155; }
    tr:last-child td { border-bottom: 0; }
    code { background: #eef3f8; border: 1px solid var(--line); border-radius: 5px; padding: 2px 5px; }
    .empty { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; color: var(--muted); }
    .status { border-radius: 999px; padding: 3px 8px; font-size: 12px; font-weight: 700; display: inline-block; }
    .new { background: #dcfce7; color: var(--ok); }
    .known { background: #e0f2fe; color: #075985; }
    .changed-ip { background: #fef3c7; color: var(--warn); }
    .offline { background: #fee2e2; color: var(--danger); }
    .tabs { margin-top: 0; }
    .tabbar { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 12px; background: #e8eef5; border: 1px solid var(--line); border-radius: 8px; padding: 5px; }
    .tabbar button { background: transparent; color: var(--text); border: 1px solid transparent; border-radius: 6px; min-height: 36px; }
    .tabbar button.active { background: var(--panel); border-color: #c7d2df; color: var(--accent-strong); box-shadow: 0 1px 2px rgba(15, 23, 42, .08); }
    .tabbar button span { color: var(--muted); font-weight: 650; margin-left: 5px; }
    .tabbar.compact button { min-height: 34px; padding: 7px 10px; }
    .tabpanel { display: none; }
    .tabpanel.active { display: block; }
    .history-form { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }
    @media (max-width: 860px) {
      main, header { padding-left: 14px; padding-right: 14px; }
      .summary { grid-template-columns: 1fr 1fr; }
      .device-tabs-head, .section-head { align-items: flex-start; flex-direction: column; }
      input { min-width: 0; width: 100%; }
      .inline-form input[type="number"] { width: 88px; min-width: 88px; }
    }
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
      <form class="inline-form" method="post" action="/autoscan">
        <span>{{ if .AutoRunning }}Auto scan on{{ else }}Auto scan off{{ end }}</span>
        <input type="number" min="1" name="interval" value="{{ .AutoInterval }}" aria-label="Auto scan interval seconds">
        <span>sec</span>
        {{ if .AutoRunning }}
        <button type="submit" name="action" value="stop">Stop</button>
        {{ else }}
        <button type="submit" name="action" value="start">Start</button>
        {{ end }}
      </form>
    </div>
    <div class="summary">
      <div class="metric"><span>New 10 min</span><strong>{{ len .NewRecent }}</strong></div>
      <div class="metric"><span>Active</span><strong>{{ len .Active }}</strong></div>
      <div class="metric"><span>Changed IP</span><strong>{{ len .Changed }}</strong></div>
      <div class="metric"><span>Offline</span><strong>{{ len .Offline }}</strong></div>
      <div class="metric"><span>Total</span><strong>{{ len .Devices }}</strong></div>
    </div>

    <section class="highlight">
      <div class="section-head">
        <h2>New devices connected in the last 10 minutes</h2>
        <form method="post" action="/archive-new">
          <button type="submit">Archive current new</button>
        </form>
      </div>
      {{ template "devices" dict "Rows" .NewRecent }}
    </section>

    <section class="device-tabs">
      <div class="device-tabs-head">
        <h2>Devices</h2>
        <div class="subtle">{{ len .Devices }} total</div>
      </div>
      <div class="tabs" data-tabs="main">
        <div class="tabbar">
          <button type="button" class="{{ if not .HistoryQuery }}active{{ end }}" data-tab-button="main" data-tab-target="tab-active">Known active <span>{{ len .Active }}</span></button>
          <button type="button" class="{{ if .HistoryQuery }}active{{ end }}" data-tab-button="main" data-tab-target="tab-history">History</button>
          <button type="button" data-tab-button="main" data-tab-target="tab-subnets">Subnets <span>{{ len .SubnetGroups }}</span></button>
          <button type="button" data-tab-button="main" data-tab-target="tab-changed">Changed IP <span>{{ len .Changed }}</span></button>
          <button type="button" data-tab-button="main" data-tab-target="tab-offline">Offline <span>{{ len .Offline }}</span></button>
          <button type="button" data-tab-button="main" data-tab-target="tab-all">All devices <span>{{ len .Devices }}</span></button>
        </div>

        <section id="tab-active" class="tabpanel {{ if not .HistoryQuery }}active{{ end }}" data-tab-panel="main">
          {{ template "devices" dict "Rows" .Active }}
        </section>

        <section id="tab-history" class="tabpanel {{ if .HistoryQuery }}active{{ end }}" data-tab-panel="main">
          <form class="history-form" method="get" action="/">
            <input name="history" value="{{ .HistoryQuery }}" placeholder="MAC or IP history">
            <button type="submit">Filter</button>
            {{ if .HistoryQuery }}<a class="button" href="/">Clear</a>{{ end }}
          </form>
          {{ template "history" .History }}
        </section>

        <section id="tab-subnets" class="tabpanel" data-tab-panel="main">
          {{ if .SubnetGroups }}
          <div class="tabs" data-tabs="subnets">
            <div class="tabbar compact">
              {{ range $idx, $group := .SubnetGroups }}
              {{ $id := tabID "subnet" .Name }}
              <button type="button" class="{{ if eq $idx 0 }}active{{ end }}" data-tab-button="subnets" data-tab-target="{{ $id }}">{{ .Name }} <span>{{ len .Devices }}</span></button>
              {{ end }}
            </div>
            {{ range $idx, $group := .SubnetGroups }}
            {{ $id := tabID "subnet" .Name }}
            <section id="{{ $id }}" class="tabpanel {{ if eq $idx 0 }}active{{ end }}" data-tab-panel="subnets">
              {{ template "devices" dict "Rows" .Devices }}
            </section>
            {{ end }}
          </div>
          {{ else }}
          <div class="empty">No subnet data yet.</div>
          {{ end }}
        </section>

        <section id="tab-changed" class="tabpanel" data-tab-panel="main">
          {{ template "devices" dict "Rows" .Changed }}
        </section>

        <section id="tab-offline" class="tabpanel" data-tab-panel="main">
          {{ template "devices" dict "Rows" .Offline }}
        </section>

        <section id="tab-all" class="tabpanel" data-tab-panel="main">
          {{ template "devices" dict "Rows" .Devices }}
        </section>
      </div>
    </section>
  </main>
  <script>
    document.querySelectorAll("[data-tabs]").forEach(function(group) {
      var name = group.getAttribute("data-tabs");
      var buttons = group.querySelectorAll('[data-tab-button="' + name + '"]');
      var panels = group.querySelectorAll('[data-tab-panel="' + name + '"]');
      buttons.forEach(function(button) {
        button.addEventListener("click", function() {
          var target = button.getAttribute("data-tab-target");
          buttons.forEach(function(item) { item.classList.remove("active"); });
          panels.forEach(function(panel) { panel.classList.remove("active"); });
          button.classList.add("active");
          var panel = document.getElementById(target);
          if (panel) {
            panel.classList.add("active");
          }
        });
      });
    });
  </script>
</body>
</html>

{{ define "devices" }}
  {{ if .Rows }}
  <div class="table-wrap"><table>
    <thead><tr><th>Status</th><th>IP</th><th>MAC</th><th>Key</th><th>Subnet</th><th>Interface</th><th>Hostname</th><th>Vendor</th><th>Last Seen</th></tr></thead>
    <tbody>
      {{ range .Rows }}
      <tr>
        <td><span class="status {{ statusClass .LastStatus }}">{{ .LastStatus }}</span></td>
        <td>{{ .IP }}</td>
        <td>{{ dash .MAC }}</td>
        <td>{{ .KeyType }}</td>
        <td>{{ dash .Subnet }}</td>
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

func recentNewDevices(state *State, window time.Duration) []DeviceRecord {
	cutoff := time.Now().UTC().Add(-window)
	var archivedBefore time.Time
	if state.NewArchivedBefore != "" {
		archivedBefore, _ = time.Parse(time.RFC3339, state.NewArchivedBefore)
	}
	seen := make(map[string]bool)
	var rows []DeviceRecord

	for i := len(state.History) - 1; i >= 0; i-- {
		event := state.History[i]
		if event.Status != "new" || seen[event.Key] {
			continue
		}
		scannedAt, err := time.Parse(time.RFC3339, event.ScannedAt)
		if err != nil || scannedAt.Before(cutoff) {
			continue
		}
		if !archivedBefore.IsZero() && !scannedAt.After(archivedBefore) {
			continue
		}
		seen[event.Key] = true
		record, ok := state.Devices[event.Key]
		if !ok {
			record = DeviceRecord{
				Key:       event.Key,
				KeyType:   event.KeyType,
				IP:        event.IP,
				MAC:       event.MAC,
				Vendor:    event.Vendor,
				Hostname:  event.Hostname,
				Interface: event.Interface,
				Subnet:    event.Subnet,
				FirstSeen: event.ScannedAt,
			}
		}
		record.LastStatus = "new"
		record.LastSeen = event.ScannedAt
		if record.FirstSeen == "" {
			record.FirstSeen = event.ScannedAt
		}
		rows = append(rows, record)
	}

	sort.Slice(rows, func(i, j int) bool {
		return rows[i].LastSeen > rows[j].LastSeen
	})
	return rows
}

func filterDevices(devices []DeviceRecord, keep func(DeviceRecord) bool) []DeviceRecord {
	rows := make([]DeviceRecord, 0, len(devices))
	for _, device := range devices {
		if keep(device) {
			rows = append(rows, device)
		}
	}
	return rows
}

func buildSubnetGroups(devices []DeviceRecord) []SubnetDeviceGroup {
	grouped := make(map[string][]DeviceRecord)
	for _, device := range devices {
		subnet := device.Subnet
		if subnet == "" {
			subnet = "unknown"
		}
		grouped[subnet] = append(grouped[subnet], device)
	}

	names := make([]string, 0, len(grouped))
	for name := range grouped {
		names = append(names, name)
	}
	sort.Strings(names)

	groups := make([]SubnetDeviceGroup, 0, len(names))
	for _, name := range names {
		rows := grouped[name]
		sort.Slice(rows, func(i, j int) bool {
			return ipToUint32(net.ParseIP(rows[i].IP)) < ipToUint32(net.ParseIP(rows[j].IP))
		})
		groups = append(groups, SubnetDeviceGroup{Name: name, Devices: rows})
	}
	return groups
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

func reportLogSummary(report ScanReport) string {
	active := len(report.New) + len(report.ChangedIP) + len(report.Known)
	return fmt.Sprintf(
		"active=%d new=%d changed_ip=%d offline=%d known=%d targets=%s",
		active,
		len(report.New),
		len(report.ChangedIP),
		len(report.Offline),
		len(report.Known),
		targetLabel(report.Targets),
	)
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

func stringSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			set[value] = true
		}
	}
	return set
}

func emptyDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func tabID(prefix, value string) string {
	var builder strings.Builder
	builder.WriteString(prefix)
	builder.WriteString("-")
	lastDash := false
	for _, char := range strings.ToLower(value) {
		isSafe := (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9')
		if isSafe {
			builder.WriteRune(char)
			lastDash = false
			continue
		}
		if !lastDash {
			builder.WriteString("-")
			lastDash = true
		}
	}
	result := strings.TrimRight(builder.String(), "-")
	if result == prefix {
		return prefix + "-unknown"
	}
	return result
}

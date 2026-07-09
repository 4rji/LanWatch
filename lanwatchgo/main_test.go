package main

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDashboardTemplateRendersTabs(t *testing.T) {
	data := dashboardData{
		Config: Config{StatePath: "test-state.json"},
		Devices: []DeviceRecord{
			{
				Key:        "aa:bb:cc:dd:ee:ff",
				KeyType:    "mac",
				IP:         "10.10.65.10",
				MAC:        "aa:bb:cc:dd:ee:ff",
				Subnet:     "10.10.65.0/24",
				LastStatus: "known",
				LastSeen:   "2026-07-09T17:00:00Z",
			},
		},
		Active: []DeviceRecord{
			{
				Key:        "aa:bb:cc:dd:ee:ff",
				KeyType:    "mac",
				IP:         "10.10.65.10",
				MAC:        "aa:bb:cc:dd:ee:ff",
				Subnet:     "10.10.65.0/24",
				LastStatus: "known",
				LastSeen:   "2026-07-09T17:00:00Z",
			},
		},
		NewRecent: []DeviceRecord{
			{
				Key:        "aa:bb:cc:dd:ee:ff",
				KeyType:    "mac",
				IP:         "10.10.65.10",
				MAC:        "aa:bb:cc:dd:ee:ff",
				Subnet:     "10.10.65.0/24",
				LastStatus: "new",
				LastSeen:   "2026-07-09T17:00:00Z",
			},
		},
		SubnetGroups: []SubnetDeviceGroup{
			{
				Name: "10.10.65.0/24",
				Devices: []DeviceRecord{
					{
						Key:        "aa:bb:cc:dd:ee:ff",
						KeyType:    "mac",
						IP:         "10.10.65.10",
						MAC:        "aa:bb:cc:dd:ee:ff",
						Subnet:     "10.10.65.0/24",
						LastStatus: "known",
						LastSeen:   "2026-07-09T17:00:00Z",
					},
				},
			},
		},
	}

	var rendered bytes.Buffer
	if err := dashboardTemplate.Execute(&rendered, data); err != nil {
		t.Fatalf("render dashboard: %v", err)
	}
	body := rendered.String()
	for _, expected := range []string{
		"New devices connected in the last 10 minutes",
		"Archive current new",
		"Auto scan",
		"Devices",
		"Known active",
		"History",
		"Subnets",
		"tab-subnets",
		"10.10.65.0/24",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("expected dashboard to contain %q", expected)
		}
	}
}

func TestSubnetAddressCount(t *testing.T) {
	_, network, err := net.ParseCIDR("172.17.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	if got := subnetAddressCount(network); got != 65536 {
		t.Fatalf("expected 65536 addresses, got %d", got)
	}
}

func TestApplyScanPositionalsInterfacesAlias(t *testing.T) {
	var interfaces stringList
	if err := applyScanPositionals([]string{"interfaces", "enp0s3"}, &interfaces); err != nil {
		t.Fatalf("apply positionals: %v", err)
	}
	if len(interfaces) != 1 || interfaces[0] != "enp0s3" {
		t.Fatalf("expected enp0s3, got %#v", interfaces)
	}
}

func TestApplyScanPositionalsRejectsWrongCommand(t *testing.T) {
	var interfaces stringList
	if err := applyScanPositionals([]string{"serve", "0.0.0.0", "50001"}, &interfaces); err == nil {
		t.Fatal("expected unexpected arguments error")
	}
}

func TestApplyBaselineRecordsKnownNotNew(t *testing.T) {
	state := &State{Devices: map[string]DeviceRecord{}}
	report := ApplyBaseline(
		state,
		[]Observation{
			{
				IP:      "10.10.65.10",
				MAC:     "aa:bb:cc:dd:ee:ff",
				Key:     "aa:bb:cc:dd:ee:ff",
				KeyType: "mac",
				Subnet:  "10.10.65.0/24",
			},
		},
		nil,
	)

	if len(report.New) != 0 {
		t.Fatalf("baseline should not create new devices, got %d", len(report.New))
	}
	if len(report.Known) != 1 {
		t.Fatalf("baseline should record one known device, got %d", len(report.Known))
	}
	if state.Devices["aa:bb:cc:dd:ee:ff"].LastStatus != "known" {
		t.Fatalf("baseline status = %q", state.Devices["aa:bb:cc:dd:ee:ff"].LastStatus)
	}
	if got := recentNewDevices(state, 10*time.Minute); len(got) != 0 {
		t.Fatalf("baseline should not appear in recent new devices, got %d", len(got))
	}
}

func TestRecentNewDevicesHonorsArchiveTimestamp(t *testing.T) {
	now := time.Now().UTC()
	key := "aa:bb:cc:dd:ee:ff"
	state := &State{
		NewArchivedBefore: now.Format(time.RFC3339),
		Devices: map[string]DeviceRecord{
			key: {
				Key:        key,
				KeyType:    "mac",
				IP:         "10.10.65.10",
				MAC:        key,
				LastStatus: "new",
				LastSeen:   now.Format(time.RFC3339),
			},
		},
		History: []HistoryEvent{
			{
				ScannedAt: now.Add(-time.Minute).Format(time.RFC3339),
				Key:       key,
				KeyType:   "mac",
				IP:        "10.10.65.10",
				MAC:       key,
				Status:    "new",
			},
		},
	}

	if got := recentNewDevices(state, 10*time.Minute); len(got) != 0 {
		t.Fatalf("archived new device should be hidden, got %d", len(got))
	}
}

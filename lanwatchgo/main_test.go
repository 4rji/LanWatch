package main

import (
	"bytes"
	"net"
	"strings"
	"testing"
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

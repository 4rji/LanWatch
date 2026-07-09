package main

import (
	"bytes"
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

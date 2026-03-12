package main

import (
	"testing"
)

func TestNewStates(t *testing.T) {
	s := NewStates()
	if !s.IsRunning() {
		t.Error("New States should be running")
	}
	if s.IsLogged() {
		t.Error("New States should not be logged")
	}
	if s.GetClientID() != "" {
		t.Error("New States should have empty clientID")
	}
}

func TestStatesSetGet(t *testing.T) {
	s := NewStates()

	s.SetClientID("client-1")
	if s.GetClientID() != "client-1" {
		t.Errorf("GetClientID() = %q, want %q", s.GetClientID(), "client-1")
	}

	s.SetAlgoID("algo-1")
	if s.GetAlgoID() != "algo-1" {
		t.Errorf("GetAlgoID() = %q, want %q", s.GetAlgoID(), "algo-1")
	}

	s.SetMacAddress("AA:BB:CC:DD:EE:FF")
	if s.GetMacAddress() != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("GetMacAddress() = %q", s.GetMacAddress())
	}

	s.SetTicket("ticket123")
	if s.GetTicket() != "ticket123" {
		t.Errorf("GetTicket() = %q", s.GetTicket())
	}

	s.SetUserIP("192.168.1.1")
	if s.GetUserIP() != "192.168.1.1" {
		t.Errorf("GetUserIP() = %q", s.GetUserIP())
	}

	s.SetAcIP("10.0.0.1")
	if s.GetAcIP() != "10.0.0.1" {
		t.Errorf("GetAcIP() = %q", s.GetAcIP())
	}

	s.SetRunning(false)
	if s.IsRunning() {
		t.Error("Should not be running after SetRunning(false)")
	}

	s.SetLogged(true)
	if !s.IsLogged() {
		t.Error("Should be logged after SetLogged(true)")
	}

	s.SetSchoolID("school-1")
	if s.GetSchoolID() != "school-1" {
		t.Errorf("GetSchoolID() = %q", s.GetSchoolID())
	}

	s.SetDomain("example.com")
	if s.GetDomain() != "example.com" {
		t.Errorf("GetDomain() = %q", s.GetDomain())
	}

	s.SetArea("area-1")
	if s.GetArea() != "area-1" {
		t.Errorf("GetArea() = %q", s.GetArea())
	}

	extra := map[string]string{"key": "value"}
	s.SetExtraCfgURL(extra)
	got := s.GetExtraCfgURL()
	if got["key"] != "value" {
		t.Errorf("GetExtraCfgURL()[key] = %q", got["key"])
	}
	// Verify it returns a copy
	got["new"] = "added"
	original := s.GetExtraCfgURL()
	if _, ok := original["new"]; ok {
		t.Error("GetExtraCfgURL should return a copy, not the original map")
	}
}

func TestRefreshStates(t *testing.T) {
	s := NewStates()
	s.RefreshStates()

	if s.GetClientID() == "" {
		t.Error("RefreshStates should set clientID")
	}
	if s.GetMacAddress() == "" {
		t.Error("RefreshStates should set macAddress")
	}
	if s.GetAlgoID() != "00000000-0000-0000-0000-000000000000" {
		t.Errorf("RefreshStates algoID = %q, want zero UUID", s.GetAlgoID())
	}

	// Two refreshes should produce different clientIDs (with very high probability)
	id1 := s.GetClientID()
	s.RefreshStates()
	id2 := s.GetClientID()
	if id1 == id2 {
		t.Logf("Warning: two RefreshStates calls produced same clientID: %s", id1)
	}
}

package main

import (
	"esurfing/utils"
	"strings"
	"sync"

	"github.com/google/uuid"
)

// States holds the global application state.
type States struct {
	mu          sync.RWMutex
	clientID    string
	algoID      string
	macAddress  string
	ticket      string
	userIP      string
	acIP        string
	running     bool
	schoolID    string
	domain      string
	area        string
	ticketURL   string
	authURL     string
	extraCfgURL map[string]string
	logged      bool
}

func NewStates() *States {
	return &States{
		running:     true,
		extraCfgURL: make(map[string]string),
	}
}

func (s *States) GetClientID() string   { s.mu.RLock(); defer s.mu.RUnlock(); return s.clientID }
func (s *States) GetAlgoID() string     { s.mu.RLock(); defer s.mu.RUnlock(); return s.algoID }
func (s *States) GetMacAddress() string { s.mu.RLock(); defer s.mu.RUnlock(); return s.macAddress }
func (s *States) GetTicket() string     { s.mu.RLock(); defer s.mu.RUnlock(); return s.ticket }
func (s *States) GetUserIP() string     { s.mu.RLock(); defer s.mu.RUnlock(); return s.userIP }
func (s *States) GetAcIP() string       { s.mu.RLock(); defer s.mu.RUnlock(); return s.acIP }
func (s *States) IsRunning() bool       { s.mu.RLock(); defer s.mu.RUnlock(); return s.running }
func (s *States) GetSchoolID() string   { s.mu.RLock(); defer s.mu.RUnlock(); return s.schoolID }
func (s *States) GetDomain() string     { s.mu.RLock(); defer s.mu.RUnlock(); return s.domain }
func (s *States) GetArea() string       { s.mu.RLock(); defer s.mu.RUnlock(); return s.area }
func (s *States) GetTicketURL() string  { s.mu.RLock(); defer s.mu.RUnlock(); return s.ticketURL }
func (s *States) GetAuthURL() string    { s.mu.RLock(); defer s.mu.RUnlock(); return s.authURL }
func (s *States) IsLogged() bool        { s.mu.RLock(); defer s.mu.RUnlock(); return s.logged }
func (s *States) GetExtraCfgURL() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make(map[string]string, len(s.extraCfgURL))
	for k, v := range s.extraCfgURL {
		cp[k] = v
	}
	return cp
}

func (s *States) SetClientID(v string)   { s.mu.Lock(); defer s.mu.Unlock(); s.clientID = v }
func (s *States) SetAlgoID(v string)     { s.mu.Lock(); defer s.mu.Unlock(); s.algoID = v }
func (s *States) SetMacAddress(v string) { s.mu.Lock(); defer s.mu.Unlock(); s.macAddress = v }
func (s *States) SetTicket(v string)     { s.mu.Lock(); defer s.mu.Unlock(); s.ticket = v }
func (s *States) SetUserIP(v string)     { s.mu.Lock(); defer s.mu.Unlock(); s.userIP = v }
func (s *States) SetAcIP(v string)       { s.mu.Lock(); defer s.mu.Unlock(); s.acIP = v }
func (s *States) SetRunning(v bool)      { s.mu.Lock(); defer s.mu.Unlock(); s.running = v }
func (s *States) SetSchoolID(v string)   { s.mu.Lock(); defer s.mu.Unlock(); s.schoolID = v }
func (s *States) SetDomain(v string)     { s.mu.Lock(); defer s.mu.Unlock(); s.domain = v }
func (s *States) SetArea(v string)       { s.mu.Lock(); defer s.mu.Unlock(); s.area = v }
func (s *States) SetTicketURL(v string)  { s.mu.Lock(); defer s.mu.Unlock(); s.ticketURL = v }
func (s *States) SetAuthURL(v string)    { s.mu.Lock(); defer s.mu.Unlock(); s.authURL = v }
func (s *States) SetLogged(v bool)       { s.mu.Lock(); defer s.mu.Unlock(); s.logged = v }
func (s *States) SetExtraCfgURL(v map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.extraCfgURL = v
}

// RefreshStates generates new client ID and MAC address.
func (s *States) RefreshStates() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clientID = strings.ToLower(uuid.New().String())
	s.algoID = "00000000-0000-0000-0000-000000000000"
	s.macAddress = utils.RandomMACAddress()
}

package network

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	userAgent     = "CCTP/android64_vpn/2093"
	requestAccept = "text/html,text/xml,application/xhtml+xml,application/x-javascript,*/*"
)

// StateProvider provides the global state values needed for requests.
type StateProvider interface {
	GetClientID() string
	GetAlgoID() string
	GetSchoolID() string
	GetDomain() string
	GetArea() string
	SetArea(string)
	SetSchoolID(string)
	SetDomain(string)
}

// redirectInterceptor is an http.RoundTripper that handles redirects with custom headers.
type redirectInterceptor struct {
	inner    http.RoundTripper
	state    StateProvider
	maxRedir int
}

func (r *redirectInterceptor) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.inner.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	redirectCount := 0
	for isRedirect(resp.StatusCode) && redirectCount < r.maxRedir {
		redirectCount++

		// Extract routing headers
		if area := resp.Header.Get("area"); area != "" {
			r.state.SetArea(area)
		}
		if schoolID := resp.Header.Get("schoolid"); schoolID != "" {
			r.state.SetSchoolID(schoolID)
		}
		if domain := resp.Header.Get("domain"); domain != "" {
			r.state.SetDomain(domain)
		}

		location := resp.Header.Get("Location")
		if location == "" {
			break
		}

		// Close old response body
		resp.Body.Close()

		newReq, err := http.NewRequest(req.Method, location, req.Body)
		if err != nil {
			return nil, err
		}
		// Copy headers
		for k, v := range req.Header {
			newReq.Header[k] = v
		}
		// Add routing headers if not present
		if r.state.GetSchoolID() != "" && newReq.Header.Get("CDC-SchoolId") == "" {
			newReq.Header.Set("CDC-SchoolId", r.state.GetSchoolID())
		}
		if r.state.GetDomain() != "" && newReq.Header.Get("CDC-Domain") == "" {
			newReq.Header.Set("CDC-Domain", r.state.GetDomain())
		}
		if r.state.GetArea() != "" && newReq.Header.Get("CDC-Area") == "" {
			newReq.Header.Set("CDC-Area", r.state.GetArea())
		}

		resp, err = r.inner.RoundTrip(newReq)
		if err != nil {
			return nil, err
		}
		req = newReq
	}
	return resp, nil
}

func isRedirect(code int) bool {
	return code == 301 || code == 302 || code == 303 || code == 307 || code == 308
}

// NewHTTPClient creates a configured HTTP client with redirect handling.
func NewHTTPClient(state StateProvider) *http.Client {
	transport := &redirectInterceptor{
		inner:    http.DefaultTransport,
		state:    state,
		maxRedir: 5,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Post sends a POST request with authentication headers.
func Post(client *http.Client, url, data string, state StateProvider, extraHeaders map[string]string) (string, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", requestAccept)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// MD5 checksum
	hash := md5.Sum([]byte(data))
	req.Header.Set("CDC-Checksum", hex.EncodeToString(hash[:]))
	req.Header.Set("Client-ID", state.GetClientID())
	req.Header.Set("Algo-ID", state.GetAlgoID())

	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}

	return string(body), nil
}

// PostRaw sends a POST request and returns raw bytes (for binary responses like ZSM).
func PostRaw(client *http.Client, url, data string, state StateProvider) ([]byte, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", requestAccept)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	hash := md5.Sum([]byte(data))
	req.Header.Set("CDC-Checksum", hex.EncodeToString(hash[:]))
	req.Header.Set("Client-ID", state.GetClientID())
	req.Header.Set("Algo-ID", state.GetAlgoID())

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	return body, nil
}

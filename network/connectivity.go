package network

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"esurfing/model"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"esurfing/utils"
)

const (
	captiveURL     = "http://connect.rom.miui.com/generate_204"
	portalStartTag = "<!--//config.campus.js.chinatelecom.com"
	portalEndTag   = "//config.campus.js.chinatelecom.com-->"
	authKey        = "Eshore!@#"
)

// ConnectivityStatus represents the network connectivity status.
type ConnectivityStatus int

const (
	StatusSuccess ConnectivityStatus = iota
	StatusRequireAuthorization
	StatusRequestError
)

// ConfigResult holds the parsed portal config.
type ConfigResult struct {
	Status      ConnectivityStatus
	AuthURL     string
	TicketURL   string
	UserIP      string
	AcIP        string
	SchoolID    string
	Domain      string
	Area        string
	ExtraCfgURL map[string]string
}

// DetectConfig performs captive portal detection and parses configuration.
func DetectConfig(state StateProvider) ConfigResult {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &redirectInterceptor{
			inner:    http.DefaultTransport,
			state:    state,
			maxRedir: 5,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", captiveURL, nil)
	if err != nil {
		return ConfigResult{Status: StatusRequestError}
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", requestAccept)
	req.Header.Set("Client-ID", state.GetClientID())

	resp, err := client.Do(req)
	if err != nil {
		return ConfigResult{Status: StatusRequestError}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return ConfigResult{Status: StatusRequestError}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ConfigResult{Status: StatusRequestError}
	}

	content := string(body)
	portalConfig := utils.ExtractBetweenTags(content, portalStartTag, portalEndTag)

	if portalConfig == "" {
		return ConfigResult{Status: StatusSuccess}
	}

	result := ConfigResult{
		Status:      StatusRequireAuthorization,
		ExtraCfgURL: make(map[string]string),
	}

	result.AuthURL = extractXMLTag(portalConfig, "auth-url")
	result.TicketURL = extractXMLTag(portalConfig, "ticket-url")

	// Parse extra config URLs from funcfg elements
	parseFuncCfg(portalConfig, result.ExtraCfgURL)

	if result.AuthURL == "" || result.TicketURL == "" {
		return ConfigResult{Status: StatusRequestError}
	}

	// Parse userIp and acIp from ticket URL
	parsedURL, err := url.Parse(result.TicketURL)
	if err != nil {
		return ConfigResult{Status: StatusRequestError}
	}

	result.UserIP = parsedURL.Query().Get("wlanuserip")
	result.AcIP = parsedURL.Query().Get("wlanacip")

	if result.UserIP == "" || result.AcIP == "" {
		return ConfigResult{Status: StatusRequestError}
	}

	// Extract area/schoolid/domain from redirect headers if present
	if area := resp.Header.Get("area"); area != "" {
		result.Area = area
	}
	if schoolID := resp.Header.Get("schoolid"); schoolID != "" {
		result.SchoolID = schoolID
	}
	if domain := resp.Header.Get("domain"); domain != "" {
		result.Domain = domain
	}

	return result
}

// extractXMLTag is a simple XML tag extractor (no proper XML parsing needed for these simple tags).
func extractXMLTag(xml, tag string) string {
	startTag := "<" + tag + ">"
	endTag := "</" + tag + ">"
	start := strings.Index(xml, startTag)
	if start == -1 {
		return ""
	}
	start += len(startTag)
	end := strings.Index(xml[start:], endTag)
	if end == -1 {
		return ""
	}
	return xml[start : start+end]
}

// parseFuncCfg parses funcfg elements from the portal config.
func parseFuncCfg(config string, result map[string]string) {
	// Simple parser for <TagName enable="1" url="..." /> patterns
	pos := 0
	for pos < len(config) {
		funcStart := strings.Index(config[pos:], "<funcfg>")
		if funcStart == -1 {
			break
		}
		funcEnd := strings.Index(config[pos+funcStart:], "</funcfg>")
		if funcEnd == -1 {
			break
		}
		section := config[pos+funcStart : pos+funcStart+funcEnd+len("</funcfg>")]
		// Parse individual elements within funcfg
		parseFuncCfgElements(section, result)
		pos = pos + funcStart + funcEnd + len("</funcfg>")
	}
}

func parseFuncCfgElements(section string, result map[string]string) {
	pos := 0
	for pos < len(section) {
		tagStart := strings.Index(section[pos:], "<")
		if tagStart == -1 {
			break
		}
		tagEnd := strings.Index(section[pos+tagStart:], ">")
		if tagEnd == -1 {
			break
		}
		element := section[pos+tagStart : pos+tagStart+tagEnd+1]
		if strings.Contains(element, "enable=\"1\"") && strings.Contains(element, "url=\"") {
			// Extract tag name
			nameEnd := strings.IndexAny(element[1:], " />")
			if nameEnd > 0 {
				tagName := element[1 : 1+nameEnd]
				// Extract URL
				urlStart := strings.Index(element, "url=\"")
				if urlStart != -1 {
					urlStart += 5
					urlEnd := strings.Index(element[urlStart:], "\"")
					if urlEnd > 0 {
						urlVal := element[urlStart : urlStart+urlEnd]
						result[tagName] = urlVal
					}
				}
			}
		}
		pos = pos + tagStart + tagEnd + 1
	}
}

// CheckVerifyCodeStatus checks if SMS verification is required.
func CheckVerifyCodeStatus(state StateProvider, httpClient *http.Client, username string, extraCfg map[string]string) bool {
	return requestVerifyCode(state, httpClient, username, "QueryVerificateCodeStatus", "11062000", extraCfg)
}

// GetVerifyCode requests a new SMS verification code.
func GetVerifyCode(state StateProvider, httpClient *http.Client, username string, extraCfg map[string]string) bool {
	return requestVerifyCode(state, httpClient, username, "QueryAuthCode", "0", extraCfg)
}

func requestVerifyCode(state StateProvider, httpClient *http.Client, username, reqType, successCode string, extraCfg map[string]string) bool {
	cfgURL, ok := extraCfg[reqType]
	if !ok || cfgURL == "" {
		return false
	}

	timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
	schoolID := state.GetSchoolID()

	hash := md5.Sum([]byte(schoolID + timestamp + authKey))
	authenticator := strings.ToUpper(hex.EncodeToString(hash[:]))

	reqBody := model.RequireVerificate{
		SchoolID:      schoolID,
		Username:      username,
		Timestamp:     timestamp,
		Authenticator: authenticator,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return false
	}

	req, err := http.NewRequest("POST", cfgURL, strings.NewReader(string(jsonData)))
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "okhttp/3.4.1")
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	var result model.ResponseRequireVerificate
	if err := json.Unmarshal(body, &result); err != nil {
		return false
	}

	return result.ResCode == successCode
}

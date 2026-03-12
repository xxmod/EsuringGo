package main

import (
	"bufio"
	"esurfing/network"
	"esurfing/utils"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// xmlEscape escapes special XML characters in user input.
func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&apos;")
	return r.Replace(s)
}

// Client manages the authentication lifecycle.
type Client struct {
	options    Options
	states     *States
	session    *Session
	httpClient *http.Client
	keepURL    string
	termURL    string
	keepRetry  string
	retryCount int
	tick       int64
}

// Options holds login credentials.
type Options struct {
	LoginUser     string
	LoginPassword string
	SMSCode       string
}

func NewClient(opts Options, states *States, session *Session) *Client {
	httpClient := network.NewHTTPClient(states)
	return &Client{
		options:    opts,
		states:     states,
		session:    session,
		httpClient: httpClient,
	}
}

// Run starts the main client loop.
func (c *Client) Run() {
	for c.states.IsRunning() {
		status := network.DetectConfig(c.states)

		switch status.Status {
		case network.StatusSuccess:
			if c.session.IsInitialized() && c.states.IsLogged() {
				nowMs := time.Now().UnixMilli()
				retryMs, err := strconv.ParseInt(c.keepRetry, 10, 64)
				if err == nil && nowMs-c.tick >= retryMs*1000 {
					log.Println("Send Keep Packet")
					if err := c.heartbeat(c.states.GetTicket()); err != nil {
						log.Printf("Heartbeat error: %v", err)
						c.states.SetLogged(false)
						continue
					}
					log.Printf("Next Retry: %s", c.keepRetry)
					c.tick = time.Now().UnixMilli()
				}
			} else {
				log.Println("The network has been connected.")
			}
			time.Sleep(1 * time.Second)

		case network.StatusRequireAuthorization:
			c.states.SetLogged(false)
			// Apply detected config to states
			c.states.SetAuthURL(status.AuthURL)
			c.states.SetTicketURL(status.TicketURL)
			c.states.SetUserIP(status.UserIP)
			c.states.SetAcIP(status.AcIP)
			if status.SchoolID != "" {
				c.states.SetSchoolID(status.SchoolID)
			}
			if status.Domain != "" {
				c.states.SetDomain(status.Domain)
			}
			if status.Area != "" {
				c.states.SetArea(status.Area)
			}
			if len(status.ExtraCfgURL) > 0 {
				c.states.SetExtraCfgURL(status.ExtraCfgURL)
			}
			c.authorization()

		case network.StatusRequestError:
			log.Println("Request Error")
			time.Sleep(5 * time.Second)
		}
	}
}

func (c *Client) authorization() {
	var code string
	if strings.TrimSpace(c.options.SMSCode) == "" {
		code = c.checkSMSVerify()
	} else {
		code = c.options.SMSCode
	}

	fmt.Printf("SMS Code is: %s\n", code)

	c.initSession()

	if !c.session.IsInitialized() {
		if c.retryCount >= 5 {
			log.Println("Unable to find algorithm implementation, please restart the application or try version 1.8.0 or below.")
			c.states.SetRunning(false)
		}
		c.retryCount++
		return
	}

	c.retryCount = 0
	c.states.SetAlgoID(c.session.GetAlgoID())
	log.Printf("Algo Id: %s", c.session.GetAlgoID())
	log.Printf("Client IP: %s", c.states.GetUserIP())
	log.Printf("AC IP: %s", c.states.GetAcIP())

	ticket, err := c.getTicket()
	if err != nil {
		log.Printf("Get ticket error: %v", err)
		return
	}
	c.states.SetTicket(ticket)
	log.Printf("Ticket: %s", c.states.GetTicket())

	if err := c.login(code); err != nil {
		log.Printf("Login error: %v", err)
		return
	}

	if c.keepURL == "" {
		log.Println("KeepUrl is empty.")
		c.session.Free()
		c.states.SetRunning(false)
		return
	}

	c.tick = time.Now().UnixMilli()
	c.states.SetLogged(true)
	log.Println("The login has been authorized.")
}

func (c *Client) checkSMSVerify() string {
	extraCfg := c.states.GetExtraCfgURL()
	if network.CheckVerifyCodeStatus(c.states, c.httpClient, c.options.LoginUser, extraCfg) &&
		network.GetVerifyCode(c.states, c.httpClient, c.options.LoginUser, extraCfg) {
		log.Println("This login requires a SMS verification code.")
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("Input Code: ")
			input, _ := reader.ReadString('\n')
			code := strings.TrimSpace(input)
			if code != "" {
				return code
			}
		}
	}
	return ""
}

func (c *Client) initSession() {
	body, err := network.PostRaw(c.httpClient, c.states.GetTicketURL(), c.states.GetAlgoID(), c.states)
	if err != nil {
		log.Printf("Init session error: %v", err)
		return
	}
	c.session.Initialize(body)
}

func (c *Client) getTicket() (string, error) {
	payload := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<request>
    <user-agent>CCTP/android64_vpn/2093</user-agent>
    <client-id>%s</client-id>
    <local-time>%s</local-time>
    <host-name>%s</host-name>
    <ipv4>%s</ipv4>
    <ipv6></ipv6>
    <mac>%s</mac>
    <ostag>%s</ostag>
    <gwip>%s</gwip>
</request>`,
		c.states.GetClientID(),
		utils.GetTime(),
		HostName,
		c.states.GetUserIP(),
		c.states.GetMacAddress(),
		HostName,
		c.states.GetAcIP(),
	)

	encrypted, err := c.session.Encrypt(payload)
	if err != nil {
		return "", fmt.Errorf("encrypt ticket payload: %w", err)
	}
	data, err := network.Post(c.httpClient, c.states.GetTicketURL(), encrypted, c.states, nil)
	if err != nil {
		return "", err
	}

	decrypted, err := c.session.Decrypt(data)
	if err != nil {
		return "", fmt.Errorf("decrypt ticket response: %w", err)
	}
	ticket := extractXMLTag(decrypted, "ticket")
	return ticket, nil
}

func (c *Client) login(code string) error {
	verify := ""
	if strings.TrimSpace(code) != "" {
		verify = "<verify>" + xmlEscape(code) + "</verify>"
	}

	payload := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<request>
    <user-agent>CCTP/android64_vpn/2093</user-agent>
    <client-id>%s</client-id>
    <ticket>%s</ticket>
    <local-time>%s</local-time>
    <userid>%s</userid>
    <passwd>%s</passwd>
    %s
</request>`,
		c.states.GetClientID(),
		c.states.GetTicket(),
		utils.GetTime(),
		xmlEscape(c.options.LoginUser),
		xmlEscape(c.options.LoginPassword),
		verify,
	)

	encrypted, err := c.session.Encrypt(payload)
	if err != nil {
		return fmt.Errorf("encrypt login payload: %w", err)
	}
	data, err := network.Post(c.httpClient, c.states.GetAuthURL(), encrypted, c.states, nil)
	if err != nil {
		return err
	}

	decrypted, err := c.session.Decrypt(data)
	if err != nil {
		return fmt.Errorf("decrypt login response: %w", err)
	}
	c.keepURL = extractXMLTag(decrypted, "keep-url")
	c.termURL = extractXMLTag(decrypted, "term-url")
	c.keepRetry = extractXMLTag(decrypted, "keep-retry")

	log.Printf("Keep Url: %s", c.keepURL)
	log.Printf("Term Url: %s", c.termURL)
	log.Printf("Keep Retry: %s", c.keepRetry)

	return nil
}

func (c *Client) heartbeat(ticket string) error {
	payload := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<request>
    <user-agent>CCTP/android64_vpn/2093</user-agent>
    <client-id>%s</client-id>
    <local-time>%s</local-time>
    <host-name>%s</host-name>
    <ipv4>%s</ipv4>
    <ticket>%s</ticket>
    <ipv6></ipv6>
    <mac>%s</mac>
    <ostag>%s</ostag>
</request>`,
		c.states.GetClientID(),
		utils.GetTime(),
		HostName,
		c.states.GetUserIP(),
		ticket,
		c.states.GetMacAddress(),
		HostName,
	)

	encrypted, err := c.session.Encrypt(payload)
	if err != nil {
		return fmt.Errorf("encrypt heartbeat payload: %w", err)
	}
	data, err := network.Post(c.httpClient, c.keepURL, encrypted, c.states, nil)
	if err != nil {
		return err
	}

	decrypted, err := c.session.Decrypt(data)
	if err != nil {
		return fmt.Errorf("decrypt heartbeat response: %w", err)
	}
	interval := extractXMLTag(decrypted, "interval")
	if interval != "" {
		c.keepRetry = interval
	}
	return nil
}

// Term sends the termination request to log out.
func (c *Client) Term() {
	payload := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<request>
    <user-agent>CCTP/android64_vpn/2093</user-agent>
    <client-id>%s</client-id>
    <local-time>%s</local-time>
    <host-name>%s</host-name>
    <ipv4>%s</ipv4>
    <ticket>%s</ticket>
    <ipv6></ipv6>
    <mac>%s</mac>
    <ostag>%s</ostag>
</request>`,
		c.states.GetClientID(),
		utils.GetTime(),
		HostName,
		c.states.GetUserIP(),
		c.states.GetTicket(),
		c.states.GetMacAddress(),
		HostName,
	)

	encrypted, err := c.session.Encrypt(payload)
	if err != nil {
		log.Printf("encrypt term payload: %v", err)
		return
	}
	_, _ = network.Post(c.httpClient, c.termURL, encrypted, c.states, nil)
}

// extractXMLTag is a simple XML tag value extractor.
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

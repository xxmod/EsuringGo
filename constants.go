package main

import "esurfing/utils"

const (
	UserAgent      = "CCTP/android64_vpn/2093"
	RequestAccept  = "text/html,text/xml,application/xhtml+xml,application/x-javascript,*/*"
	CaptiveURL     = "http://connect.rom.miui.com/generate_204"
	PortalEndTag   = "//config.campus.js.chinatelecom.com-->"
	PortalStartTag = "<!--//config.campus.js.chinatelecom.com"
	AuthKey        = "Eshore!@#"
)

var HostName = utils.RandomString(10)

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"strings"
)

// profileAccount is one mail account in an Apple configuration profile.
type profileAccount struct {
	Address  string
	Password string
}

// profileUUID derives a stable identifier, so that installing a newer profile
// for the same account replaces the old one instead of adding a second.
func profileUUID(parts ...string) string {
	sum := sha256.Sum256([]byte("mailbridge profile\x00" + strings.Join(parts, "\x00")))
	b := sum[:16]
	b[6] = b[6]&0x0f | 0x50 // a name-based UUID
	b[8] = b[8]&0x3f | 0x80
	return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]))
}

// profileID turns free text into something allowed in a payload identifier.
func profileID(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			return r
		}
		return '-'
	}, s)
}

// plist writes property list values. Keys come in the order given, which is
// alphabetical in the callers below, like Apple's own tools write them.
type plist struct{ bytes.Buffer }

func (p *plist) key(k string) { fmt.Fprintf(p, "<key>%s</key>", k) }

func (p *plist) str(k, v string) {
	p.key(k)
	p.WriteString("<string>")
	_ = xml.EscapeText(p, []byte(v))
	p.WriteString("</string>\n")
}

func (p *plist) num(k string, v int) {
	p.key(k)
	fmt.Fprintf(p, "<integer>%d</integer>\n", v)
}

func (p *plist) yes(k string) {
	p.key(k)
	p.WriteString("<true/>\n")
}

// appleMailProfile builds a configuration profile (.mobileconfig) that sets
// up the accounts in Mail on iPhone, iPad and Mac. Both servers are marked as
// using SSL, which is how Apple's Mail spells "encrypted": it covers TLS from
// the first byte as well as STARTTLS.
//
// The profile contains the bridge password, so that nothing has to be typed.
func appleMailProfile(host string, imapPort, smtpPort int, accounts []profileAccount) []byte {
	var p plist
	p.WriteString(xml.Header)
	p.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	p.WriteString("<plist version=\"1.0\">\n<dict>\n")

	p.key("PayloadContent")
	p.WriteString("\n<array>\n")
	for _, a := range accounts {
		p.WriteString("<dict>\n")
		p.str("EmailAccountDescription", "Proton Mail ("+a.Address+")")
		p.str("EmailAccountType", "EmailTypeIMAP")
		p.str("EmailAddress", a.Address)
		p.str("IncomingMailServerAuthentication", "EmailAuthPassword")
		p.str("IncomingMailServerHostName", host)
		p.num("IncomingMailServerPortNumber", imapPort)
		p.yes("IncomingMailServerUseSSL")
		p.str("IncomingMailServerUsername", a.Address)
		p.str("IncomingPassword", a.Password)
		p.str("OutgoingMailServerAuthentication", "EmailAuthPassword")
		p.str("OutgoingMailServerHostName", host)
		p.num("OutgoingMailServerPortNumber", smtpPort)
		p.yes("OutgoingMailServerUseSSL")
		p.str("OutgoingMailServerUsername", a.Address)
		p.str("OutgoingPassword", a.Password)
		p.yes("OutgoingPasswordSameAsIncomingPassword")
		p.str("PayloadDescription", "Proton Mail for "+a.Address+" through Proton Mail Bridge on "+host+".")
		p.str("PayloadDisplayName", "Proton Mail ("+a.Address+")")
		p.str("PayloadIdentifier", "mailbridge."+profileID(host)+"."+profileID(a.Address)+".mail")
		p.str("PayloadType", "com.apple.mail.managed")
		p.str("PayloadUUID", profileUUID("mail", host, a.Address))
		p.num("PayloadVersion", 1)
		p.WriteString("</dict>\n")
	}
	p.WriteString("</array>\n")

	first := accounts[0].Address
	p.str("PayloadDescription", "Sets up Mail for Proton Mail through Proton Mail Bridge on "+host+".")
	p.str("PayloadDisplayName", "Proton Mail ("+first+")")
	p.str("PayloadIdentifier", "mailbridge."+profileID(host)+"."+profileID(first))
	p.str("PayloadOrganization", "mailbridge on "+host)
	p.str("PayloadType", "Configuration")
	p.str("PayloadUUID", profileUUID("profile", host, first))
	p.num("PayloadVersion", 1)
	p.WriteString("</dict>\n</plist>\n")
	return p.Bytes()
}

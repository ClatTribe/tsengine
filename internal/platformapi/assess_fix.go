package platformapi

import "fmt"

// assess_fix.go is the free "fix-it" layer of the public scanner: for every check the domain FAILS,
// the assessment carries the exact copy-paste remediation. The scanner finds the gap (assess.go /
// assess_web.go); this hands the founder the fix — which is also the GTM "want the 3-line DNS fix?"
// motion. Pure (string in, string out); the fixes are static, accurate, provider-noted snippets.

type checkFix struct {
	Summary  string       `json:"summary"`
	Snippets []fixSnippet `json:"snippets"`
}

type fixSnippet struct {
	Label string `json:"label"`
	Lang  string `json:"lang"`
	Code  string `json:"code"`
}

// ifFail returns f only when the check failed (cond), so callers can attach a fix inline.
func ifFail(failed bool, f *checkFix) *checkFix {
	if failed {
		return f
	}
	return nil
}

func dmarcFix(domain string) *checkFix {
	return &checkFix{
		Summary: "Publish a DMARC policy so mail spoofing your domain is rejected. Roll out at p=none for ~1 week to monitor your real senders, then move to p=reject.",
		Snippets: []fixSnippet{{
			Label: "DNS TXT record",
			Lang:  "dns",
			Code: fmt.Sprintf("Name:  _dmarc.%s\nType:  TXT\nValue: v=DMARC1; p=reject; rua=mailto:dmarc@%s; adkim=s; aspf=s", domain, domain),
		}},
	}
}

func spfFix(domain string) *checkFix {
	return &checkFix{
		Summary: "Publish an SPF record listing who may send mail for your domain. The include below is Google Workspace — replace it with your provider's (Microsoft 365: include:spf.protection.outlook.com). End with -all to hard-fail everything else.",
		Snippets: []fixSnippet{{
			Label: "DNS TXT record",
			Lang:  "dns",
			Code:  fmt.Sprintf("Name:  %s\nType:  TXT\nValue: v=spf1 include:_spf.google.com -all", domain),
		}},
	}
}

func dkimFix() *checkFix {
	return &checkFix{
		Summary: "Enable DKIM in your mail provider — it generates a key and gives you a DNS record to publish. We can't guess the selector, so do it from the provider console.",
		Snippets: []fixSnippet{{
			Label: "Steps",
			Lang:  "text",
			Code:  "Google Workspace: Admin → Apps → Google Workspace → Gmail → Authenticate email → Generate new record → publish the TXT it shows.\nMicrosoft 365: Defender → Email & collaboration → Policies → Email authentication → DKIM → enable for your domain.",
		}},
	}
}

func httpsFix() *checkFix {
	return &checkFix{
		Summary: "Redirect all HTTP to HTTPS and serve a valid TLS 1.2+ cert (free via Let's Encrypt, or one click on Cloudflare/Vercel/your host).",
		Snippets: []fixSnippet{{
			Label: "nginx",
			Lang:  "nginx",
			Code:  "server {\n  listen 80;\n  server_name _;\n  return 301 https://$host$request_uri;\n}",
		}},
	}
}

func hstsFix() *checkFix {
	return &checkFix{
		Summary: "Add HSTS so browsers refuse to talk to your domain over plain HTTP. Cloudflare: SSL/TLS → Edge Certificates → enable HSTS.",
		Snippets: []fixSnippet{{
			Label: "nginx / response header",
			Lang:  "nginx",
			Code:  `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;`,
		}},
	}
}

func cspFix() *checkFix {
	return &checkFix{
		Summary: "Add a Content-Security-Policy. Start strict and loosen only what your app needs — this is your strongest XSS/injection defense.",
		Snippets: []fixSnippet{{
			Label: "nginx / response header",
			Lang:  "nginx",
			Code:  `add_header Content-Security-Policy "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; object-src 'none'" always;`,
		}},
	}
}

func clickjackFix() *checkFix {
	return &checkFix{
		Summary: "Block clickjacking and MIME-sniffing with two response headers.",
		Snippets: []fixSnippet{{
			Label: "nginx / response headers",
			Lang:  "nginx",
			Code:  "add_header X-Frame-Options \"DENY\" always;\nadd_header X-Content-Type-Options \"nosniff\" always;",
		}},
	}
}

func securityTxtFix(domain string) *checkFix {
	return &checkFix{
		Summary: "Publish a security.txt so researchers — and enterprise questionnaires — find your disclosure contact. Serve it at /.well-known/security.txt.",
		Snippets: []fixSnippet{{
			Label: fmt.Sprintf("https://%s/.well-known/security.txt", domain),
			Lang:  "text",
			Code:  fmt.Sprintf("Contact: mailto:security@%s\nExpires: 2027-01-01T00:00:00Z\nPreferred-Languages: en\nCanonical: https://%s/.well-known/security.txt", domain, domain),
		}},
	}
}

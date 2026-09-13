package sspm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// FetchOktaPosture reads the org's configuration through the onboarded token. Scopes are the READ
// halves: okta.policies.read, okta.apiTokens.read, okta.threatInsights.read, okta.networkZones.read.
// Each endpoint is read independently; one that cannot be read is NAMED in Unread and its checks
// decline (nil pointers), so a token with fewer scopes produces fewer verdicts, never a cleaner org.
// Reading NOTHING is an error: a token that reaches no endpoint must not produce an org with no
// findings.
func FetchOktaPosture(ctx context.Context, orgURL, orgName, token string, hc *http.Client) (OktaOrg, error) {
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	orgURL = strings.TrimRight(orgURL, "/")
	if orgURL == "" {
		return OktaOrg{}, fmt.Errorf("okta posture sync: no org URL (OKTA_ORG_URL)")
	}
	if strings.TrimSpace(token) == "" {
		return OktaOrg{}, fmt.Errorf("okta posture sync: empty token")
	}
	org := OktaOrg{Name: nz(orgName, strings.TrimPrefix(strings.TrimPrefix(orgURL, "https://"), "http://")), Unread: map[string]string{},
		SignOnRules: []OktaSignOnRule{}, Passwords: []OktaPasswordPolicy{}, MFAEnroll: []OktaMFAEnrollPolicy{}, APITokens: []OktaAPIToken{}}
	read := 0

	// Sign-on policies and their rules — the factor decision lives on the rule.
	var signOn []oktaPolicy
	if err := oktaGetAll(ctx, hc, orgURL+"/api/v1/policies?type=OKTA_SIGN_ON", token, &signOn); err != nil {
		org.Unread["policies:OKTA_SIGN_ON"] = err.Error()
	} else {
		read++
		for _, p := range signOn {
			var rules []oktaSignOnRuleAPI
			if err := oktaGetAll(ctx, hc, orgURL+"/api/v1/policies/"+p.ID+"/rules", token, &rules); err != nil {
				org.Unread["policies/"+p.ID+"/rules"] = err.Error()
				continue
			}
			for _, r := range rules {
				rule := OktaSignOnRule{Policy: p.Name, Rule: r.Name, Status: r.Status, Access: r.Actions.Signon.Access, NetworkScope: r.Conditions.Network.Connection}
				if r.Actions.Signon.Access != "" {
					rf := r.Actions.Signon.RequireFactor
					rule.RequireFactor = &rf
				}
				if r.Actions.Signon.Session != nil {
					m := r.Actions.Signon.Session.MaxSessionLifetimeMinutes
					rule.SessionMinutes = &m
					pc := r.Actions.Signon.Session.UsePersistentCookie
					rule.PersistCookie = &pc
				}
				org.SignOnRules = append(org.SignOnRules, rule)
			}
		}
	}

	var pw []oktaPolicy
	if err := oktaGetAll(ctx, hc, orgURL+"/api/v1/policies?type=PASSWORD", token, &pw); err != nil {
		org.Unread["policies:PASSWORD"] = err.Error()
	} else {
		read++
		for _, p := range pw {
			pp := OktaPasswordPolicy{Policy: p.Name, Status: p.Status}
			if p.Settings.Password != nil {
				ml := p.Settings.Password.Complexity.MinLength
				pp.MinLength = &ml
				cx := p.Settings.Password.Complexity.MinLowerCase + p.Settings.Password.Complexity.MinUpperCase +
					p.Settings.Password.Complexity.MinNumber + p.Settings.Password.Complexity.MinSymbol
				pp.Complexity = &cx
				lm := p.Settings.Password.Lockout.MaxAttempts
				pp.LockoutMax = &lm
				cc := p.Settings.Password.Complexity.Dictionary.Common.Exclude
				pp.CommonCheck = &cc
			}
			org.Passwords = append(org.Passwords, pp)
		}
	}

	var mfa []oktaPolicy
	if err := oktaGetAll(ctx, hc, orgURL+"/api/v1/policies?type=MFA_ENROLL", token, &mfa); err != nil {
		org.Unread["policies:MFA_ENROLL"] = err.Error()
	} else {
		read++
		for _, p := range mfa {
			ep := OktaMFAEnrollPolicy{Policy: p.Name, Status: p.Status}
			for _, f := range p.Settings.Factors {
				switch strings.ToUpper(f.Enroll.Self) {
				case "REQUIRED":
					ep.Required++
				case "OPTIONAL":
					ep.Optional++
				}
			}
			for _, a := range p.Settings.Authenticators {
				switch strings.ToUpper(a.Enroll.Self) {
				case "REQUIRED":
					ep.Required++
				case "OPTIONAL":
					ep.Optional++
				}
			}
			org.MFAEnroll = append(org.MFAEnroll, ep)
		}
	}

	var toks []struct {
		Name     string    `json:"name"`
		Created  time.Time `json:"created"`
		LastUsed time.Time `json:"lastUpdated"`
		ClientID string    `json:"clientName"`
		UserID   string    `json:"userId"`
	}
	if err := oktaGetAll(ctx, hc, orgURL+"/api/v1/api-tokens", token, &toks); err != nil {
		org.Unread["api-tokens"] = err.Error()
	} else {
		read++
		for _, t := range toks {
			org.APITokens = append(org.APITokens, OktaAPIToken{Name: t.Name, Created: t.Created, LastUsed: t.LastUsed, Client: nz(t.ClientID, t.UserID)})
		}
	}

	var ti struct {
		Action string `json:"action"`
	}
	if err := oktaGetOne(ctx, hc, orgURL+"/api/v1/threats/configuration", token, &ti); err != nil {
		org.Unread["threats/configuration"] = err.Error()
	} else {
		read++
		a := strings.ToLower(ti.Action)
		org.ThreatInsight = &a
	}

	var zones []struct {
		ID string `json:"id"`
	}
	if err := oktaGetAll(ctx, hc, orgURL+"/api/v1/zones", token, &zones); err != nil {
		org.Unread["zones"] = err.Error()
	} else {
		read++
		n := len(zones)
		org.NetworkZones = &n
	}

	if read == 0 {
		return OktaOrg{}, fmt.Errorf("okta posture sync: no endpoint could be read (check okta.policies.read / okta.apiTokens.read / okta.threatInsights.read)")
	}
	return org, nil
}

type oktaPolicy struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Settings struct {
		Password *struct {
			Complexity struct {
				MinLength    int `json:"minLength"`
				MinLowerCase int `json:"minLowerCase"`
				MinUpperCase int `json:"minUpperCase"`
				MinNumber    int `json:"minNumber"`
				MinSymbol    int `json:"minSymbol"`
				Dictionary   struct {
					Common struct {
						Exclude bool `json:"exclude"`
					} `json:"common"`
				} `json:"dictionary"`
			} `json:"complexity"`
			Lockout struct {
				MaxAttempts int `json:"maxAttempts"`
			} `json:"lockout"`
		} `json:"password"`
		Factors        map[string]oktaEnroll `json:"factors"`
		Authenticators []oktaEnroll          `json:"authenticators"`
	} `json:"settings"`
}

type oktaEnroll struct {
	Enroll struct {
		Self string `json:"self"`
	} `json:"enroll"`
}

type oktaSignOnRuleAPI struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Conditions struct {
		Network struct {
			Connection string `json:"connection"`
		} `json:"network"`
	} `json:"conditions"`
	Actions struct {
		Signon struct {
			Access        string `json:"access"`
			RequireFactor bool   `json:"requireFactor"`
			Session       *struct {
				MaxSessionLifetimeMinutes int  `json:"maxSessionLifetimeMinutes"`
				UsePersistentCookie       bool `json:"usePersistentCookie"`
			} `json:"session"`
		} `json:"signon"`
	} `json:"actions"`
}

// oktaGetAll walks Link rel="next" paging for a list endpoint.
func oktaGetAll[T any](ctx context.Context, hc *http.Client, first, token string, out *[]T) error {
	next := first
	for p := 0; next != "" && p < 20; p++ {
		var page []T
		link, err := oktaGetPage(ctx, hc, next, token, &page)
		if err != nil {
			return err
		}
		*out = append(*out, page...)
		next = link
	}
	return nil
}

func oktaGetOne(ctx context.Context, hc *http.Client, u, token string, out any) error {
	_, err := oktaGetPage(ctx, hc, u, token, out)
	return err
}

func oktaGetPage(ctx context.Context, hc *http.Client, u, token string, out any) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	res, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, rerr := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if rerr != nil {
		return "", rerr
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", res.StatusCode)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return "", fmt.Errorf("response is not the expected shape: %w", err)
	}
	for _, l := range res.Header.Values("Link") {
		for _, part := range strings.Split(l, ",") {
			if strings.Contains(part, `rel="next"`) {
				s, e := strings.Index(part, "<"), strings.Index(part, ">")
				if s >= 0 && e > s {
					return part[s+1 : e], nil
				}
			}
		}
	}
	return "", nil
}

package training

import "strings"

// Module is one unit of the curriculum.
//
// The Body is the whole reason TierDelivered can mean anything. A module with no content is a
// checkbox, and a checkbox that produces an audit record saying someone was trained is the worst
// thing in this package — so the content is here, in the repository, reviewable, and short enough
// that a person will actually read it rather than click past it.
type Module struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// Why is the one-line answer to "why am I being shown this", which is the difference between
	// training somebody reads and training somebody dismisses.
	Why string `json:"why"`
	// RecurEveryDays is how long a completion stays current. 365 throughout: annual is what the
	// frameworks below ask for, and a shorter interval we invented would be a burden we cannot
	// justify to the person doing it.
	RecurEveryDays int `json:"recur_every_days"`
	// Controls are the control refs this module speaks to, per framework key (grc.Frameworks). Every
	// one is a real awareness-training control — the mapping is not stretched to look comprehensive,
	// because a training module does not satisfy an access-control requirement no matter how much a
	// coverage number would like it to (§8: map only where a real nexus exists).
	Controls map[string][]string `json:"controls"`
	// Body is the content, in paragraphs. Rendered in order.
	Body []string `json:"body"`
}

// Curriculum is the set of modules a person is expected to complete.
type Curriculum struct {
	// Version identifies the content. A completion is evidence about the content that was shown, so
	// the version is recorded alongside it in the same spirit as pinning a corpus into a scan (§10).
	Version string   `json:"version"`
	Modules []Module `json:"modules"`
}

// Module looks one up by id.
func (c Curriculum) Module(id string) (Module, bool) {
	id = strings.TrimSpace(id)
	for _, m := range c.Modules {
		if m.ID == id {
			return m, true
		}
	}
	return Module{}, false
}

// awarenessControls is the control set every module in this curriculum speaks to. It is shared
// because it is genuinely the same nexus in each case — the frameworks ask for a security-awareness
// programme, not for a per-topic control — and writing it once stops five copies drifting apart.
func awarenessControls() map[string][]string {
	return map[string][]string{
		"soc2":         {"CC1.4", "CC2.2"},
		"iso27001":     {"A.6.3"},
		"pci":          {"12.6.1", "12.6.3"},
		"hipaa":        {"164.308(a)(5)"},
		"nist_800_53":  {"AT-2"},
		"nist_800_171": {"3.2.1", "3.2.2"},
		"cis_v8":       {"14.1", "14.2"},
	}
}

// Default is the standard security-awareness curriculum: the five topics an auditor expects a small
// company to cover, written for someone who does not work in security.
//
// Five, not fifteen. A curriculum long enough to feel thorough is one people click through, and a
// click-through produces the same audit record as attention while teaching nobody anything.
func Default() Curriculum {
	return Curriculum{
		Version: "1.0",
		Modules: []Module{
			{
				ID:             "phishing",
				Title:          "Phishing and social engineering",
				Why:            "Almost every breach that starts with a person starts here.",
				RecurEveryDays: 365,
				Controls:       awarenessControls(),
				Body: []string{
					"A phishing message is one that wants you to act before you think. It will usually give you a reason to hurry — an invoice about to lapse, a login that will be locked, a request from someone senior who is in a meeting and cannot be called. The urgency is the attack. Almost nothing that is genuinely urgent arrives by surprise from someone you cannot reach.",
					"Check the sender's actual address rather than the display name, which anyone can set to anything. Hover a link and read where it really goes: attackers register domains that look right at a glance — a hyphen added, a letter swapped, a real company name in front of a domain they own. If a message asks you to sign in, do not use its link. Open the site the way you normally would and see whether the same thing is waiting for you there.",
					"Attacks do not only arrive by email. The same request comes by text, by WhatsApp, through a LinkedIn message, or as a phone call from someone who already knows your manager's name and last week's project — details that are easy to find and are used precisely because they sound like proof. A caller who resists being called back on a number you already have is telling you something.",
					"The requests worth the most suspicion are the ones that move money or access: changing bank details for a supplier, buying gift cards, approving a login prompt you did not trigger, or sharing a code someone reads out to you. No legitimate colleague and no real support desk will ever ask for a one-time code.",
					"If you think you have clicked something, say so immediately. Nobody here will be annoyed with you for reporting it, and the difference between a contained incident and a serious one is usually measured in the minutes before someone spoke up. Reporting a message that turns out to be genuine costs nothing at all.",
				},
			},
			{
				ID:             "accounts",
				Title:          "Passwords, MFA and your accounts",
				Why:            "Stolen credentials are the most common way in, and the cheapest to shut off.",
				RecurEveryDays: 365,
				Controls:       awarenessControls(),
				Body: []string{
					"Use a password manager and let it generate every password. The point is not that a generated password is harder to guess — it is that a unique one per site means a breach at one company cannot be replayed against another. Credentials stolen from an unrelated service and reused elsewhere is one of the most common ways an attacker gets in, and it needs no skill at all.",
					"Turn on multi-factor authentication everywhere it is offered, starting with your work email, because everything else can be reset through it. An app-based code or a hardware key is meaningfully stronger than a code by SMS: a phone number can be moved to an attacker's SIM by someone convincing enough on a call to your mobile provider.",
					"Never approve a login prompt you did not start. Attackers with a working password will push prompts repeatedly, often late at night, until someone taps approve to make it stop. That single tap is the whole attack. If prompts arrive unbidden, deny them and report it — it means your password is already known.",
					"Your work accounts belong to the company, not to you personally, and that is not a formality: it is why access is removed when someone leaves, why sharing a login is a problem even between people who both should have access, and why a personal account should never hold work data. Shared logins make it impossible to say who did what, which is the question every investigation opens with.",
					"If you ever suspect a password is exposed — you typed it into a page that turned out to be fake, or it appeared in a breach notification — change it and tell someone. Changing it quietly is better than nothing, but it leaves everyone else guessing about what else that password protected.",
				},
			},
			{
				ID:             "data",
				Title:          "Handling customer data",
				Why:            "Most data loss is ordinary work done in the wrong place.",
				RecurEveryDays: 365,
				Controls:       awarenessControls(),
				Body: []string{
					"Customer data is anything that identifies a person or belongs to a customer's business: names and email addresses, support tickets, account records, exports and backups, screenshots that happen to contain a real record. It does not stop being customer data because it is in a spreadsheet, a chat message, or a ticket you opened to get help.",
					"Take the least you need and keep it for as long as you need it. A full export pulled to answer one question becomes a copy nobody remembers, sitting in a downloads folder or a personal drive, outside every control the company has. If you must pull one, delete it when you are done.",
					"Keep it in the systems the company runs. Pasting real records into a personal account, a note-taking app, an AI assistant, or a public paste site moves the data somewhere with different rules, and in most cases somewhere it cannot be deleted afterwards. When you need to share an example, redact it or invent one — a fake record demonstrates the same bug.",
					"Check who you are sharing with before you share. Most accidental disclosure is a link set to 'anyone with the link' rather than a break-in, an autocompleted address on an email, or a channel that has a guest in it. These are ordinary mistakes made by careful people, which is exactly why the habit of checking is worth more than the intention not to make them.",
					"If data goes somewhere it should not have, report it the same day. There are legal clocks that start when a company becomes aware of a disclosure, and they are measured in days — the sooner it is known, the more of the response is a choice rather than a scramble.",
				},
			},
			{
				ID:             "devices",
				Title:          "Your laptop and your phone",
				Why:            "The device in your bag holds the same access your accounts do.",
				RecurEveryDays: 365,
				Controls:       awarenessControls(),
				Body: []string{
					"Keep full-disk encryption on. It is the one control that decides whether a stolen laptop is an inconvenience or a data breach — without it, everything on the disk can be read by anyone who picks it up, no password required. It is on by default on modern machines; the risk is somebody having turned it off.",
					"Lock your screen when you step away, and set it to lock itself. An unlocked machine in a co-working space, a cafe, or an office with visitors is every account you are signed into, standing open. Install operating-system and browser updates when they are offered rather than deferring them for weeks: the updates that matter most are the ones released because an exploited flaw became public.",
					"Install software from the places your operating system or your company points you to. Browser extensions deserve particular care — they can read every page you visit, including the ones with customer data on them, and a popular extension changing hands is a routine way that access is sold.",
					"Public Wi-Fi is mostly fine for browsing an encrypted site and a poor place to do anything sensitive. Public charging ports and unknown USB drives are worth avoiding outright; a cable or a stick is a plausible way to hand someone a device that is not what it appears to be.",
					"If a device is lost or stolen, report it immediately, before you look for it. Access can be revoked and a device can be wiped remotely, and both of those are worth doing while the outcome is still uncertain rather than after it is settled.",
				},
			},
			{
				ID:             "reporting",
				Title:          "Spotting and reporting an incident",
				Why:            "The response starts when somebody says something, and not before.",
				RecurEveryDays: 365,
				Controls:       awarenessControls(),
				Body: []string{
					"You do not need to be sure that something is an incident to report it. The people who handle it would far rather rule out ten harmless things than find out about a real one a week late, and 'this felt odd' is a perfectly good reason to raise something.",
					"Things worth reporting: a message you clicked before thinking, a login prompt you did not trigger, a file or link shared with the wrong people, a customer telling you they received something strange from us, a machine behaving unusually, a device lost, a credential typed into a page that turned out not to be ours.",
					"When you report, say what happened and when, in plain terms — what you clicked, what you entered, what you saw, what time it was. Rough timings are fine and far better than none. Include the message or a screenshot if you still have it; forwarding a suspicious email intact preserves details that a retyped summary loses.",
					"Do not try to clean it up first. Deleting the message, wiping the file, or resetting the machine destroys the evidence needed to work out what actually happened and whether anyone else was affected. Preserve it as it is and let the response decide.",
					"Nobody is in trouble for reporting an incident they caused. That is not a courtesy — it is the only way this works. A team that fears blame reports late, and late reporting is what turns a contained problem into a disclosed one.",
				},
			},
		},
	}
}

package grc

// The standardized question corpus — a SIG-Lite / CAIQ-shaped set, split by how each question
// can honestly be answered.
//
// WHY THIS IS NOT 261 QUESTIONS. CAIQ v4 has 261 and SIG Lite around 300, and importing one
// wholesale is the obvious move that makes the deliverable WORSE. Most of those questions ask
// about things no scanner can see — HR screening, physical security, BCM rehearsals, legal
// terms — so a wholesale import turns a document with ten unanswered rows into one with two
// hundred and thirty. The proportion answered does not improve; the honesty layer just prints
// more of the same admission, and the reader has more to wade through to reach it.
//
// So the corpus grows along BOTH axes instead:
//
//   - OBSERVED questions expand to everything the engine genuinely evidences. That is far more
//     than the original ten — identity, cloud, endpoints, SaaS, vendors, external exposure,
//     detection and response are all already assessed and none of them were being asked about.
//   - ATTESTED questions cover what no scan can reach, answered by a named human and rendered
//     as theirs. This is how every vendor answers these; what would be dishonest is rendering
//     an assertion identically to an observation.
//
// A question earns an OBSERVED slot only when a detector in this tree actually produces the
// signal. `Sources` names what has to be connected, and it is checked at answer time — so an
// observed question with nothing connected reads "Not assessed", never "Yes". Adding a
// question for a capability we do not have would be the one move this file must never make:
// it would sit at "Not assessed" forever while implying a check exists.
//
// Control ids are the ones the detectors and the CWE crosswalk really emit (CC6.1, CC6.3,
// CC6.6, CC6.7, CC6.8, CC7.1, CC7.2, CC7.3, CC8.1, CC9.2 and their PCI/CIS/ISO/NIST
// counterparts), because that mapping is what lets a real gap flip an answer to In Progress.

func standardQuestionnaire() []QQuestion {
	out := make([]QQuestion, 0, len(observedQuestions)+len(attestedQuestions))
	out = append(out, observedQuestions...)
	return append(out, attestedQuestions...)
}

// QuestionByID looks up one question in the corpus. Returns nil when the id is unknown — the
// caller decides what that means, and the attest endpoint treats it as a 404 rather than
// creating an answer to a question nobody asked.
func QuestionByID(id string) *QQuestion {
	for _, q := range standardQuestionnaire() {
		if q.ID == id {
			c := q
			return &c
		}
	}
	return nil
}

// obs is a small constructor so the corpus below reads as data rather than as struct literals.
func obs(id, domain, text string, sources []string, controls map[string][]string) QQuestion {
	return QQuestion{ID: id, Domain: domain, Text: text, Evidence: QObserved, Sources: sources, Controls: controls}
}

// att declares a question only a human can answer, together with WHY we cannot.
func att(id, domain, text, why string, controls map[string][]string) QQuestion {
	return QQuestion{ID: id, Domain: domain, Text: text, Evidence: QAttested, Why: why, Controls: controls}
}

var observedQuestions = []QQuestion{
	// --- Access control (internal/operate, internal/sspm, internal/cloudengine) ---
	obs("AC-1", "Access Control", "Is multi-factor authentication enforced for administrative and user access?",
		[]string{"identity"}, map[string][]string{"soc2": {"CC6.1"}, "pci": {"8.3.1"}, "cis_v8": {"6.5"}}),
	obs("AC-2", "Access Control", "Are access privileges restricted to least privilege and reviewed regularly?",
		[]string{"identity", "cloud"}, map[string][]string{"soc2": {"CC6.3"}, "iso27001": {"A.9.2"}}),
	obs("AC-3", "Access Control", "Are accounts deprovisioned promptly when someone leaves?",
		[]string{"identity"}, map[string][]string{"soc2": {"CC6.2"}, "cis_v8": {"6.2"}}),
	obs("AC-4", "Access Control", "Is workforce access federated through a single identity provider (SSO)?",
		[]string{"identity"}, map[string][]string{"soc2": {"CC6.1"}, "cis_v8": {"6.7"}}),
	obs("AC-5", "Access Control", "Are third-party application grants inventoried and reviewed for risky scopes?",
		[]string{"identity", "saas"}, map[string][]string{"soc2": {"CC6.3", "CC9.2"}, "iso27001": {"A.15.1"}}),
	obs("AC-6", "Access Control", "Are privileged cloud roles limited, and is privilege escalation monitored?",
		[]string{"cloud"}, map[string][]string{"soc2": {"CC6.3"}, "cis_v8": {"5.4"}, "nist_800_53": {"AC-6"}}),

	// --- Cryptography (internal/tlsscan, cloud posture) ---
	obs("CR-1", "Cryptography", "Is customer data encrypted in transit using current TLS configurations?",
		[]string{"web", "api", "domain"}, map[string][]string{"soc2": {"CC6.7"}, "pci": {"4.2.1"}}),
	obs("CR-2", "Cryptography", "Is customer data encrypted at rest?",
		[]string{"cloud"}, map[string][]string{"soc2": {"CC6.7"}, "pci": {"3.5.1"}, "nist_800_53": {"SC-28"}}),
	obs("CR-3", "Cryptography", "Are TLS certificates monitored for expiry and unexpected issuance?",
		[]string{"domain", "web"}, map[string][]string{"soc2": {"CC6.7"}, "cis_v8": {"3.10"}}),

	// --- Vulnerability management (repository/container/cloud scanning + internal/detect) ---
	obs("VM-1", "Vulnerability Management", "Are systems and dependencies continuously scanned for known vulnerabilities?",
		[]string{"repository", "container", "cloud"}, map[string][]string{"soc2": {"CC7.1"}, "pci": {"6.3.1"}, "cis_v8": {"7.5"}}),
	obs("VM-2", "Vulnerability Management", "Are application security issues (injection, XSS, leaked secrets) identified before release?",
		[]string{"repository", "web", "api"}, map[string][]string{"soc2": {"CC8.1"}, "pci": {"6.2.4"}}),
	obs("VM-3", "Vulnerability Management", "Are container images scanned for vulnerable packages and misconfiguration?",
		[]string{"container"}, map[string][]string{"soc2": {"CC7.1"}, "cis_v8": {"7.7"}}),
	obs("VM-4", "Vulnerability Management", "Are remediation timelines defined by severity, and are fixes verified?",
		[]string{"repository", "container", "cloud", "web"}, map[string][]string{"soc2": {"CC7.1"}, "pci": {"6.3.3"}}),
	obs("VM-5", "Vulnerability Management", "Is penetration testing performed against production applications?",
		[]string{"web", "api"}, map[string][]string{"soc2": {"CC7.1"}, "pci": {"11.4.1"}}),
	obs("VM-6", "Vulnerability Management", "Are secrets and credentials kept out of source control?",
		[]string{"repository"}, map[string][]string{"soc2": {"CC6.1"}, "cis_v8": {"3.11"}}),

	// --- Software development (internal/prbot, repository asset) ---
	obs("SD-1", "Secure Development", "Is every code change reviewed before it reaches production?",
		[]string{"repository"}, map[string][]string{"soc2": {"CC8.1"}, "iso27001": {"A.14.2"}}),
	obs("SD-2", "Secure Development", "Are security checks enforced in the CI pipeline, blocking merges on serious findings?",
		[]string{"repository"}, map[string][]string{"soc2": {"CC8.1"}, "pci": {"6.2.4"}}),

	// --- Infrastructure and cloud (internal/cloudengine, internal/clouddrift) ---
	obs("IN-1", "Infrastructure", "Is cloud storage prevented from being publicly accessible?",
		[]string{"cloud"}, map[string][]string{"soc2": {"CC6.6"}, "cis_v8": {"3.3"}}),
	obs("IN-2", "Infrastructure", "Is inbound network access restricted rather than open to the internet?",
		[]string{"cloud", "ip"}, map[string][]string{"soc2": {"CC6.6"}, "nist_800_53": {"SC-7"}}),
	obs("IN-3", "Infrastructure", "Are cloud configurations assessed against a hardening baseline?",
		[]string{"cloud", "container"}, map[string][]string{"soc2": {"CC6.8"}, "cis_v8": {"4.1"}}),
	obs("IN-4", "Infrastructure", "Are unauthorized changes to the production environment detected?",
		[]string{"cloud"}, map[string][]string{"soc2": {"CC8.1"}, "nist_800_53": {"CM-3"}}),

	// --- Logging and monitoring (internal/detect, cloud posture) ---
	obs("LM-1", "Logging & Monitoring", "Are security-relevant events logged and monitored for anomalies?",
		[]string{"cloud"}, map[string][]string{"soc2": {"CC7.2"}, "nist_csf": {"DE.CM-8"}}),
	obs("LM-2", "Logging & Monitoring", "Are suspicious identity events (impossible travel, MFA removal, password spray) detected?",
		[]string{"identity"}, map[string][]string{"soc2": {"CC7.2"}, "cis_v8": {"8.11"}}),

	// --- Incident response (internal/detect, internal/certin) ---
	obs("IR-1", "Incident Response", "Are security incidents detected, tracked, and resolved through a defined process?",
		[]string{"cloud", "identity", "repository", "web"}, map[string][]string{"soc2": {"CC7.3", "CC7.4"}, "nist_csf": {"RS.RP-1"}}),
	obs("IR-2", "Incident Response", "Is there a defined escalation path with named responders and acknowledgement targets?",
		[]string{"cloud", "identity", "repository", "web"}, map[string][]string{"soc2": {"CC7.3"}, "iso27001": {"A.16.1"}}),

	// --- Endpoints (internal/deviceposture) ---
	obs("EP-1", "Endpoint Security", "Is full-disk encryption enforced on employee devices?",
		[]string{"device"}, map[string][]string{"soc2": {"CC6.7"}, "hipaa": {"164.312(a)(2)(iv)"}, "nist_800_53": {"SC-28"}}),
	obs("EP-2", "Endpoint Security", "Do employee devices run endpoint protection and receive security updates?",
		[]string{"device"}, map[string][]string{"soc2": {"CC6.8"}, "cis_v8": {"10.1"}}),
	obs("EP-3", "Endpoint Security", "Are screen locks and device-level access controls enforced?",
		[]string{"device"}, map[string][]string{"soc2": {"CC6.1"}, "nist_800_53": {"AC-11"}}),

	// --- SaaS posture (internal/sspm) ---
	obs("SA-1", "SaaS Security", "Are SaaS applications configured to require MFA and restrict external sharing?",
		[]string{"saas", "identity"}, map[string][]string{"soc2": {"CC6.1", "CC6.6"}, "cis_v8": {"6.5"}}),

	// --- Third party (internal/tprm) ---
	obs("VR-1", "Vendor / Third-Party", "Are sub-processors and vendors assessed before and during the relationship?",
		[]string{"vendor"}, map[string][]string{"soc2": {"CC9.2"}, "gdpr": {"Art. 28"}, "iso27001": {"A.5.19"}}),
	obs("VR-2", "Vendor / Third-Party", "Do vendors handling personal data have a data processing agreement in place?",
		[]string{"vendor"}, map[string][]string{"soc2": {"CC9.2"}, "gdpr": {"Art. 28"}}),

	// --- External exposure (internal/osint) ---
	obs("EX-1", "External Exposure", "Is the internet-facing attack surface continuously inventoried?",
		[]string{"domain", "ip", "web"}, map[string][]string{"soc2": {"CC6.6", "CC7.1"}, "cis_v8": {"1.1"}}),
	obs("EX-2", "External Exposure", "Are leaked corporate credentials and exposed secrets monitored for?",
		[]string{"domain", "repository"}, map[string][]string{"soc2": {"CC6.1"}, "gdpr": {"Art. 33"}}),
	obs("EM-1", "Email Security", "Is the sending domain protected against spoofing (SPF, DKIM, DMARC enforced)?",
		[]string{"domain", "identity"}, map[string][]string{"cis_v8": {"9.5"}, "nist_csf": {"PR.DS-2"}}),

	// --- Data (internal/dataplatform, internal/dataclass) ---
	// The source is "cloud", not a separate "data": cloudgraph classifies data stores and
	// assesses the access paths to them, and that is a connected cloud account. internal/
	// dataplatform goes deeper (warehouse grants) but arrives as a posted snapshot that stamps
	// no posture source, so nothing could report whether it ran — naming it here would put a
	// source on the page that can never turn from missing to present.
	obs("DA-1", "Data Protection", "Is access to data stores and warehouses restricted and reviewed?",
		[]string{"cloud"}, map[string][]string{"soc2": {"CC6.3"}, "pci": {"7.2.1"}}),

	// --- Personnel (internal/training) ---
	//
	// PROMOTED from the attested tier. Its old reason for being attested — "training completion lives
	// in an HR or LMS system we do not read" — stopped being true when the programme landed: the
	// completions are ours, the curriculum is ours, and expiry against the annual requirement is
	// computed rather than claimed. A question stays attested because no detector can answer it, not
	// as a habit, and leaving it there would have understated evidence we hold.
	//
	// Safe to observe because both halves are grounded. The "training" source is stamped by the
	// monitoring pass ONLY when a roster exists, so a company whose workforce we cannot see reads
	// "Not assessed" rather than Yes; and anyone who owes training raises a finding citing CC1.4 and
	// PCI 12.6.1, which turns this answer to "In progress" — so a roster that has done nothing can
	// never answer Yes.
	obs("HR-2", "Personnel", "Do employees receive security awareness training at least annually?",
		[]string{"training"}, map[string][]string{"soc2": {"CC1.4"}, "pci": {"12.6.1"}}),
}

var attestedQuestions = []QQuestion{
	att("HR-1", "Personnel", "Are background checks performed on employees with access to customer data?",
		"Employment records are not something any scanner can see.",
		map[string][]string{"soc2": {"CC1.4"}, "iso27001": {"A.7.1"}}),
	att("HR-3", "Personnel", "Are employees bound by confidentiality agreements?",
		"A signed agreement is a legal artifact, not an observable system state.",
		map[string][]string{"soc2": {"CC1.4"}, "iso27001": {"A.6.6"}}),

	att("PH-1", "Physical Security", "Are offices and data-processing facilities physically access-controlled?",
		"Physical premises are outside anything the engine can reach. If you host entirely on a cloud provider, this is usually answered by their own certifications.",
		map[string][]string{"soc2": {"CC6.4"}, "iso27001": {"A.7.2"}}),

	att("BC-1", "Business Continuity", "Is there a documented business continuity and disaster recovery plan?",
		"We can see that backups exist; whether a plan is documented is a separate fact.",
		map[string][]string{"soc2": {"A1.2"}, "iso27001": {"A.5.29"}}),
	att("BC-2", "Business Continuity", "Has the recovery plan been tested within the last twelve months?",
		"A rehearsal leaves no trace any scanner reads — and an untested plan is the thing this question exists to find.",
		map[string][]string{"soc2": {"A1.3"}, "iso27001": {"A.5.30"}}),
	att("BC-3", "Business Continuity", "Are backups taken, encrypted, and restore-tested?",
		"Backup configuration is partly visible in cloud posture; whether a restore was actually exercised is not.",
		map[string][]string{"soc2": {"A1.2"}, "cis_v8": {"11.5"}}),

	att("GV-1", "Governance", "Is a formal risk assessment performed at least annually?",
		"The register is in the product, but whether the review actually happened is a statement about your process.",
		map[string][]string{"soc2": {"CC3.2"}, "iso27001": {"A.5.7"}}),
	att("GV-2", "Governance", "Is there a named individual accountable for information security?",
		"An accountability assignment is an organizational fact, not a system one.",
		map[string][]string{"soc2": {"CC1.3"}, "iso27001": {"A.5.2"}}),
	att("GV-3", "Governance", "Do you carry cyber liability insurance?",
		"A policy is a commercial arrangement with no technical footprint.",
		map[string][]string{"soc2": {"CC3.1"}}),

	att("DP-1", "Data Protection", "Is customer data segregated between tenants?",
		"Whether isolation is logical, physical or per-instance is an architectural claim; we can observe access controls but not attest to the design.",
		map[string][]string{"soc2": {"CC6.1"}, "iso27001": {"A.8.31"}}),
	att("DP-2", "Data Protection", "Are documented data retention and secure deletion procedures in place?",
		"Retention is a policy decision; we can see what exists, not what you have decided to keep.",
		map[string][]string{"gdpr": {"Art. 5"}, "iso27001": {"A.8.10"}}),
	att("DP-3", "Data Protection", "Is customer data returned or destroyed on termination, on request?",
		"An offboarding commitment is contractual and takes effect after the relationship ends.",
		map[string][]string{"gdpr": {"Art. 28"}, "soc2": {"CC6.5"}}),
	att("DP-4", "Data Protection", "In which jurisdictions is customer data stored and processed?",
		"Cloud posture shows the regions in use; the authoritative answer covers every processor, including ones we are not connected to.",
		map[string][]string{"gdpr": {"Art. 44"}, "iso27001": {"A.5.34"}}),

	att("IN-5", "Incident Response", "Will affected customers be notified of a breach, and within what timeframe?",
		"A notification commitment is a contractual promise about future conduct.",
		map[string][]string{"gdpr": {"Art. 33", "Art. 34"}, "soc2": {"CC7.4"}}),
	att("VR-3", "Vendor / Third-Party", "Are customers notified before a new sub-processor is engaged?",
		"A notification process is a commitment, not an observable state.",
		map[string][]string{"gdpr": {"Art. 28"}, "soc2": {"CC9.2"}}),
	att("CM-2", "Change Management", "Are production changes approved and documented under a change-management process?",
		"We can see that code review is enforced; whether a wider change process is followed for infrastructure and vendors is yours to state.",
		map[string][]string{"soc2": {"CC8.1"}, "iso27001": {"A.8.32"}}),
}

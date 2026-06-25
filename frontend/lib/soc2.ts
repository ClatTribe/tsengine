// The free SOC 2 readiness self-assessment (MoFu tool). A founder answers a short set of grounded
// questions across the SOC 2 control areas that actually sink seed-stage companies; the score is a
// pure tally of their own answers (no fabrication — it's a self-report) plus a prioritized gap list.
// No account, no backend. Linked from the MoFu blog post; CTAs out to /scan and /signup.

export type Answer = "yes" | "partial" | "no";

export interface Question {
  id: string;
  area: string;
  cc: string; // the SOC 2 Trust Services Criteria reference
  text: string;
  tip: string; // what to do if the answer isn't "yes"
}

export const QUESTIONS: Question[] = [
  // Access control — where most early findings land
  { id: "mfa", area: "Access control", cc: "CC6.1", text: "Is MFA required for all employees on email, code hosting, and cloud?", tip: "Enforce MFA org-wide in Google/M365/Okta and on GitHub/GitLab and your cloud root + IAM users." },
  { id: "sso", area: "Access control", cc: "CC6.1", text: "Do you use SSO / a central identity provider instead of per-app passwords?", tip: "Route apps through one IdP so access is granted and revoked in one place." },
  { id: "offboarding", area: "Access control", cc: "CC6.2", text: "When someone leaves, is their access revoked the same day, by a documented process?", tip: "Write a one-page off-boarding checklist and run it the day someone departs." },
  { id: "least-priv", area: "Access control", cc: "CC6.3", text: "Is access least-privilege — no shared admin logins, people only have what their role needs?", tip: "Remove standing admin, kill shared logins, review who has production access." },

  // Change management
  { id: "code-review", area: "Change management", cc: "CC8.1", text: "Does code require review (an approved PR) before it merges to production?", tip: "Turn on branch protection requiring at least one approving review before merge." },
  { id: "deploy-record", area: "Change management", cc: "CC8.1", text: "Is there a record of what shipped and when (a deploy history)?", tip: "Your CI/CD or git tags already give you this — make sure it's retained." },

  // Vulnerability management
  { id: "sast-sca", area: "Vulnerability management", cc: "CC7.1", text: "Do you scan your code and dependencies for vulnerabilities?", tip: "Run SAST + dependency (SCA) scanning in CI on every change." },
  { id: "remediation-sla", area: "Vulnerability management", cc: "CC7.1", text: "Do you fix critical/high vulnerabilities within a defined time window?", tip: "Set a simple SLA (e.g. criticals in 7 days) and track it." },
  { id: "cspm", area: "Vulnerability management", cc: "CC7.1", text: "Do you scan your cloud configuration for misconfigurations?", tip: "Run a CSPM check (public buckets, open security groups, over-broad IAM)." },

  // Monitoring
  { id: "logging", area: "Monitoring", cc: "CC7.2", text: "Do you collect and retain logs from your app and cloud?", tip: "Enable CloudTrail / audit logs + app logs and keep them (90+ days)." },
  { id: "alerting", area: "Monitoring", cc: "CC7.2", text: "Would you be alerted if something broke or someone accessed something they shouldn't?", tip: "Wire critical alerts to a channel a human actually watches." },

  // Data & vendors
  { id: "vendors", area: "Data & vendors", cc: "CC9.2", text: "Do you know which third-party vendors / sub-processors touch your customer data?", tip: "Keep a sub-processor list — it's also a questionnaire and DPA requirement." },
  { id: "encryption", area: "Data & vendors", cc: "CC6.7", text: "Is customer data encrypted at rest and in transit?", tip: "TLS everywhere + encryption-at-rest on your datastores (usually a default to confirm)." },

  // Governance
  { id: "policies", area: "Governance", cc: "CC1.1", text: "Do you have written security policies your team acknowledges?", tip: "Even lightweight policies count — the point is they exist and are acknowledged." },
  { id: "owner", area: "Governance", cc: "CC1.3", text: "Is there a named person accountable for security?", tip: "Assign an owner (often a founder early on) — auditors look for clear accountability." },
];

export const AREAS = Array.from(new Set(QUESTIONS.map((q) => q.area)));

const SCORE: Record<Answer, number> = { yes: 2, partial: 1, no: 0 };

export interface AssessmentResult {
  score: number; // 0-100
  grade: string; // A-F
  answered: number;
  total: number;
  gaps: Question[]; // questions answered no/partial, worst-first (no before partial), area-ordered
}

export function scoreAssessment(answers: Record<string, Answer>): AssessmentResult {
  const total = QUESTIONS.length;
  let sum = 0;
  let answered = 0;
  for (const q of QUESTIONS) {
    const a = answers[q.id];
    if (a) {
      answered++;
      sum += SCORE[a];
    }
  }
  const max = total * 2;
  const score = max > 0 ? Math.round((sum / max) * 100) : 0;
  const gaps = QUESTIONS.filter((q) => answers[q.id] === "no" || answers[q.id] === "partial").sort((a, b) => {
    const rank = (id: string) => (answers[id] === "no" ? 0 : 1);
    return rank(a.id) - rank(b.id);
  });
  return { score, grade: grade(score), answered, total, gaps };
}

function grade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

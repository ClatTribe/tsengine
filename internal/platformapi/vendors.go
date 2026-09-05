package platformapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/tprm"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// vendors.go is the vendor REGISTER — the durable third-party inventory.
//
// # Why it had to exist
//
// The vendor set used to live only inside the body of POST /v1/tprm/ingest. The FINDINGS persisted
// and the PORTFOLIO did not, so the product could say which suppliers failed a check and could not
// answer "who are our vendors" at all. That is the same defect the Trust Center's sub-processor note
// describes from the other side — a list derived from findings names the vendors that failed and
// omits every well-managed one — and a vendor register is precisely the artifact an auditor asks for
// under SOC 2 CC9.2, GDPR Art. 28 and PCI 12.8.
//
// # One register, two doors
//
// Both the posted inventory and the register's own editor write through `saveVendors`. That is
// deliberate: this codebase has repeatedly found the same bug where two doors to one assessor
// disagree (SaaS posture enriched through one and folded through the other; device posture folded
// into compliance from the ingest and not from the live sync). A CI job posting the inventory and a
// person adding a row here must produce the same register and the same findings, or "who are our
// vendors" has two answers.
//
// # Grounding (§10)
//
// The register is DECLARED, never inferred: nothing about a vendor's name or category says whether
// they hold personal data, whether a DPA is signed, or when somebody last reviewed them. An empty
// register is reported as an empty register — never as a clean portfolio — because a company with no
// vendors recorded and a company with no vendor risk look identical in a findings list.

var vendorIDRe = regexp.MustCompile(`[^a-z0-9]+`)

// vendorID is a slug of the name, so re-posting the same inventory UPDATES each vendor rather than
// accumulating copies of it. The name is the only stable identifier a posted inventory carries.
func vendorID(name string) string {
	return strings.Trim(vendorIDRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-"), "-")
}

type vendorsResponse struct {
	Vendors []platform.Vendor `json:"vendors"`
	Summary vendorSummary     `json:"summary"`
}

// vendorSummary counts the register. Note what it does NOT contain: a compliance score. The same
// refusal the training programme makes — a single figure would blend "we hold a SOC 2 report for
// them" with "nobody has looked at this vendor since 2024", and it would rise as a customer recorded
// fewer vendors.
type vendorSummary struct {
	Total         int `json:"total"`
	Subprocessors int `json:"subprocessors"`
	SensitiveData int `json:"sensitive_data"`
	NeverReviewed int `json:"never_reviewed"`
	Unowned       int `json:"unowned"`
	// Detail states what the numbers mean, so an empty register cannot be skimmed as a clean one.
	Detail string `json:"detail"`
}

// handleListVendors returns the register.
func (d Deps) handleListVendors(w http.ResponseWriter, r *http.Request, tenantID string) {
	vs, err := d.Store.ListVendors(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	writeJSON(w, http.StatusOK, vendorsResponse{Vendors: vs, Summary: summarizeVendors(vs)})
}

func summarizeVendors(vs []platform.Vendor) vendorSummary {
	s := vendorSummary{Total: len(vs)}
	for _, v := range vs {
		if v.Subprocessor {
			s.Subprocessors++
		}
		if v.DataAccess == platform.VendorDataSensitive {
			s.SensitiveData++
		}
		if strings.TrimSpace(v.LastAssessed) == "" {
			s.NeverReviewed++
		}
		if strings.TrimSpace(v.Owner) == "" {
			s.Unowned++
		}
	}
	switch {
	case s.Total == 0:
		s.Detail = "No vendors are recorded yet. This is an empty register, not a clean one — a company " +
			"with nothing written down and a company with no vendor risk look identical here until " +
			"somebody lists who you buy from."
	case s.NeverReviewed > 0 || s.Unowned > 0:
		s.Detail = plural(s.Total, "vendor is", "vendors are") + " on the register. " +
			plural(s.NeverReviewed, "has never been reviewed", "have never been reviewed") + " and " +
			plural(s.Unowned, "has no named owner", "have no named owner") +
			" — an unowned vendor is one nobody has agreed to be accountable for, which is what an " +
			"auditor asks about first."
	default:
		s.Detail = plural(s.Total, "vendor is", "vendors are") + " on the register, each with a named " +
			"owner and a recorded review date."
	}
	return s
}

// handlePutVendor upserts one row of the register from the editor.
func (d Deps) handlePutVendor(w http.ResponseWriter, r *http.Request, tenantID string) {
	var v platform.Vendor
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&v); err != nil && err != io.EOF {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	if strings.TrimSpace(v.Name) == "" {
		// A row nobody can name cannot be reviewed, cited in a report, or matched against a posted
		// inventory later. Refused rather than stored under a blank key.
		writeJSON(w, http.StatusBadRequest, errBody("a vendor name is required"))
		return
	}
	v.Source = "register"
	saved, risks, ferr := d.saveVendors(r.Context(), tenantID, []platform.Vendor{v}, "vendor register edit")
	if ferr != nil {
		respond(w, nil, ferr)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"vendor": saved[0], "risks_detected": len(risks)})
}

// handleDeleteVendor removes one row.
func (d Deps) handleDeleteVendor(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errBody("a vendor id is required"))
		return
	}
	if err := d.Store.DeleteVendor(r.Context(), tenantID, id); err != nil {
		respond(w, nil, err)
		return
	}
	// Re-assess so the findings follow the register: a vendor removed from the inventory should not
	// keep raising risks about a relationship that has ended.
	vs, err := d.Store.ListVendors(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	if _, ferr := d.assessRegister(r.Context(), tenantID, vs, "vendor removed from the register"); ferr != nil {
		respond(w, nil, ferr)
		return
	}
	d.handleListVendors(w, r, tenantID)
}

// saveVendors upserts rows into the register and re-assesses the WHOLE register afterwards.
//
// Assessing the whole register rather than only the rows just written is the point: vendor risk is a
// property of the portfolio, and assessing a subset would leave findings standing for rows that have
// since been fixed elsewhere.
func (d Deps) saveVendors(ctx context.Context, tenantID string, in []platform.Vendor, why string) ([]platform.Vendor, []types.Finding, error) {
	now := time.Now().UTC()
	saved := make([]platform.Vendor, 0, len(in))
	for _, v := range in {
		if strings.TrimSpace(v.Name) == "" {
			continue // an unnamed vendor cannot be a register row; the caller reports the skip
		}
		v.TenantID = tenantID
		if strings.TrimSpace(v.ID) == "" {
			v.ID = vendorID(v.Name)
		}
		v.UpdatedAt = now
		if err := d.Store.PutVendor(ctx, v); err != nil {
			return nil, nil, err
		}
		saved = append(saved, v)
	}
	all, err := d.Store.ListVendors(ctx, tenantID)
	if err != nil {
		return nil, nil, err
	}
	risks, ferr := d.assessRegister(ctx, tenantID, all, why)
	if ferr != nil {
		return nil, nil, ferr
	}
	sort.Slice(saved, func(i, j int) bool { return saved[i].ID < saved[j].ID })
	return saved, risks, nil
}

// assessRegister runs tprm.Assess over the register and lands the findings the same way every other
// posture ingest does — enriched (§11), stored, folded into the compliance posture, proposed at the
// desk, and stamped as assessed so a clean portfolio is distinguishable from one nobody looked at.
//
// It is ONE path because the register has two doors. When the posted-inventory door and the editor
// door assess differently, "who are our vendors" and "what is wrong with them" stop agreeing — the
// same drift this codebase has now found three times (SaaS posture, device posture, and the sync vs
// ingest fold).
func (d Deps) assessRegister(ctx context.Context, tenantID string, vendors []platform.Vendor, why string) ([]types.Finding, error) {
	findings := enrichFindings(tprm.Assess(vendors, tprm.Options{}))
	d.markPostureAssessed(ctx, tenantID, "tprm", time.Now().UTC())
	stored := 0
	saved := make([]types.Finding, 0, len(findings))
	for i, f := range findings {
		f.ID = d.newID("tprm") + "-" + strconv.Itoa(i)
		if err := d.Store.PutFinding(ctx, tenantID, f); err != nil {
			continue
		}
		d.foldIntoPosture(ctx, tenantID, []types.Finding{f})
		saved = append(saved, f)
		stored++
	}
	d.proposeForFindings(ctx, tenantID, saved)
	if d.IncidentOpener != nil && stored > 0 {
		_, _ = d.IncidentOpener.OpenFor(ctx, tenantID, saved, nil)
	}
	if d.Recorder != nil {
		d.Recorder.Record("vendor risk assessed", "tprm",
			map[string]any{"tenant_id": tenantID, "vendors": len(vendors), "findings": stored}, why)
	}
	return saved, nil
}

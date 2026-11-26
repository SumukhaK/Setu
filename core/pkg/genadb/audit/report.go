package audit

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Format is an export format for reports.
type Format string

const (
	FormatJSON Format = "json"
	FormatCSV  Format = "csv"
	FormatHTML Format = "html"
)

// ParseFormat accepts "json", "csv" or "html" (case-insensitive).
func ParseFormat(s string) (Format, error) {
	switch f := Format(strings.ToLower(strings.TrimSpace(s))); f {
	case FormatJSON, FormatCSV, FormatHTML:
		return f, nil
	}
	return "", errorf("unknown report format %q (want json, csv or html)", s)
}

// Report is the summary an admin exports. Its JSON form is the schema in
// API_SPEC.md section 3.2 (checked by TestReportMatchesAPISpec).
type Report struct {
	GeneratedAt string           `json:"generated_at"`
	Source      string           `json:"source,omitempty"`
	Since       string           `json:"since,omitempty"`       // filter lower bound, if any
	Until       string           `json:"until,omitempty"`       // filter upper bound, if any
	FirstEvent  string           `json:"first_event,omitempty"` // ts of the first record included
	LastEvent   string           `json:"last_event,omitempty"`  // ts of the last record included
	Chain       ChainStatus      `json:"chain"`
	Totals      Totals           `json:"totals"`
	ByUser      []Group          `json:"by_user"`
	ByDevice    []Group          `json:"by_device"`
	ByOp        []Group          `json:"by_op"`
	Sessions    []SessionSummary `json:"sessions"`
	Denials     []Denial         `json:"denials"`
	Events      []Event          `json:"events,omitempty"`
}

// Totals counts records across the (filtered) log.
type Totals struct {
	Records     int   `json:"records"`
	Sessions    int   `json:"sessions"`
	Operations  int   `json:"operations"`
	Denials     int   `json:"denials"`
	Revocations int   `json:"revocations"`
	BytesUp     int64 `json:"bytes_up"`
	BytesDown   int64 `json:"bytes_down"`
	Users       int   `json:"users"`
	Devices     int   `json:"devices"`
}

// Group aggregates activity for one user, device or operation.
type Group struct {
	Key        string `json:"key"`
	Sessions   int    `json:"sessions"`
	Operations int    `json:"operations"`
	Denials    int    `json:"denials"`
	BytesUp    int64  `json:"bytes_up"`
	BytesDown  int64  `json:"bytes_down"`
}

// Denial is one refused access attempt.
type Denial struct {
	TS     string `json:"ts"`
	User   string `json:"user,omitempty"`
	Device string `json:"device,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// SessionSummary describes one session from start to end.
type SessionSummary struct {
	Session    string `json:"session"`
	User       string `json:"user,omitempty"`
	Device     string `json:"device,omitempty"`
	Transport  string `json:"transport,omitempty"`
	Start      string `json:"start,omitempty"`
	End        string `json:"end,omitempty"`
	EndReason  string `json:"end_reason,omitempty"`
	Operations int    `json:"operations"`
	BytesUp    int64  `json:"bytes_up"`
	BytesDown  int64  `json:"bytes_down"`
}

// Options filters what goes into a report.
type Options struct {
	Since, Until  time.Time // zero = unbounded
	IncludeEvents bool      // embed the raw (filtered) events in JSON reports
	Source        string    // free-text label, e.g. the log path
	// Chain, when set, replaces the status Build computes with Verify, for
	// example with VerifyFile's result, which also covers the anchor.
	Chain *ChainStatus
}

func str(e Event, k string) string {
	switch v := e[k].(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func num(e Event, k string) int64 {
	switch v := e[k].(type) {
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			f, _ := v.Float64()
			return int64(f)
		}
		return n
	case float64:
		return int64(v)
	case int:
		return int64(v)
	case int64:
		return v
	}
	return 0
}

// Build summarises events. The chain is verified over the full log, before
// any time filter is applied.
func Build(events []Event, opt Options) Report {
	r := Report{GeneratedAt: time.Now().UTC().Format(time.RFC3339), Source: opt.Source}
	if opt.Chain != nil {
		r.Chain = *opt.Chain
	} else {
		r.Chain = Verify(events)
	}
	if !opt.Since.IsZero() {
		r.Since = opt.Since.UTC().Format(time.RFC3339)
	}
	if !opt.Until.IsZero() {
		r.Until = opt.Until.UTC().Format(time.RFC3339)
	}
	users, devices, ops := map[string]*Group{}, map[string]*Group{}, map[string]*Group{}
	sessions := map[string]*SessionSummary{}
	var order []string
	group := func(m map[string]*Group, k string) *Group {
		if k == "" {
			k = "(unknown)"
		}
		g := m[k]
		if g == nil {
			g = &Group{Key: k}
			m[k] = g
		}
		return g
	}
	sess := func(e Event) *SessionSummary {
		id := str(e, "session")
		if id == "" {
			return nil
		}
		s := sessions[id]
		if s == nil {
			s = &SessionSummary{Session: id}
			sessions[id] = s
			order = append(order, id)
		}
		if v := str(e, "user"); v != "" {
			s.User = v
		}
		if v := str(e, "device"); v != "" {
			s.Device = v
		}
		if v := str(e, "transport"); v != "" {
			s.Transport = v
		}
		return s
	}
	var firstTime, lastTime time.Time
	var haveTime bool
	for _, e := range events {
		ts := str(e, "ts")
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			if !opt.Since.IsZero() && t.Before(opt.Since) {
				continue
			}
			if !opt.Until.IsZero() && t.After(opt.Until) {
				continue
			}
			if !haveTime || t.Before(firstTime) {
				firstTime, r.FirstEvent = t, ts
			}
			if !haveTime || t.After(lastTime) {
				lastTime, r.LastEvent = t, ts
			}
			haveTime = true
		}
		r.Totals.Records++
		if opt.IncludeEvents {
			r.Events = append(r.Events, e)
		}
		ev := str(e, "event")
		user, dev := str(e, "user"), str(e, "device")
		up, down := num(e, "bytes_up"), num(e, "bytes_down")
		switch ev {
		case "session_start":
			r.Totals.Sessions++
			group(users, user).Sessions++
			group(devices, dev).Sessions++
			if s := sess(e); s != nil {
				s.Start = ts
			}
		case "session_end":
			if s := sess(e); s != nil {
				s.End = ts
				s.EndReason = str(e, "reason")
				if up+down > 0 { // agent-side end records carry session totals
					s.BytesUp, s.BytesDown = up, down
				}
			}
		case "adb_op":
			r.Totals.Operations++
			r.Totals.BytesUp += up
			r.Totals.BytesDown += down
			for _, g := range []*Group{group(users, user), group(devices, dev), group(ops, str(e, "op"))} {
				g.Operations++
				g.BytesUp += up
				g.BytesDown += down
			}
			if s := sess(e); s != nil {
				s.Operations++
			}
		case "denied":
			r.Totals.Denials++
			group(users, user).Denials++
			if dev != "" {
				group(devices, dev).Denials++
			}
			r.Denials = append(r.Denials, Denial{TS: ts, User: user, Device: dev, Reason: str(e, "reason")})
		case "revoked":
			r.Totals.Revocations++
		}
	}
	r.ByUser, r.ByDevice, r.ByOp = sorted(users), sorted(devices), sorted(ops)
	r.Totals.Users, r.Totals.Devices = countKnown(users), countKnown(devices)
	for _, id := range order {
		r.Sessions = append(r.Sessions, *sessions[id])
	}
	if r.Denials == nil {
		r.Denials = []Denial{}
	}
	if r.Sessions == nil {
		r.Sessions = []SessionSummary{}
	}
	return r
}

func countKnown(m map[string]*Group) int {
	n := len(m)
	if _, ok := m["(unknown)"]; ok {
		n--
	}
	return n
}

func sorted(m map[string]*Group) []Group {
	out := make([]Group, 0, len(m))
	for _, g := range m {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Export writes the report in the given format. CSV exports one row per
// event (the raw audit trail); JSON and HTML export the summary.
func Export(w io.Writer, events []Event, f Format, opt Options) error {
	switch f {
	case FormatJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(Build(events, opt))
	case FormatCSV:
		return writeCSV(w, events, opt)
	case FormatHTML:
		return writeHTML(w, Build(events, opt))
	}
	return errorf("unknown format %q", f)
}

// CSVColumns is the fixed CSV header (API_SPEC.md section 3.2).
var CSVColumns = []string{"seq", "ts", "event", "role", "user", "token_id", "device", "session", "transport",
	"op", "path", "command", "sha256", "bytes_up", "bytes_down", "duration_ms", "result", "reason",
	"prev_event_hash", "event_hash"}

func writeCSV(w io.Writer, events []Event, opt Options) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(CSVColumns); err != nil {
		return err
	}
	for _, e := range events {
		if t, err := time.Parse(time.RFC3339Nano, str(e, "ts")); err == nil {
			if (!opt.Since.IsZero() && t.Before(opt.Since)) || (!opt.Until.IsZero() && t.After(opt.Until)) {
				continue
			}
		}
		row := make([]string, len(CSVColumns))
		for i, c := range CSVColumns {
			row[i] = csvSafe(str(e, c))
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// csvSafe neutralises spreadsheet formula injection.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		if _, err := strconv.ParseFloat(s, 64); err != nil {
			return "'" + s
		}
	}
	return s
}

var htmlTmpl = template.Must(template.New("r").Funcs(template.FuncMap{"bytes": humanBytes}).Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GenADB audit report</title>
<style>
body{font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem auto;max-width:1100px;padding:0 1rem;color:#1d2330}
h1{font-size:1.5rem;margin:0 0 .25rem}h2{font-size:1.1rem;margin:2rem 0 .5rem}
.muted{color:#5b6475}.ok{color:#11733b}.bad{color:#b42318;font-weight:600}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:.75rem;margin:1rem 0}
.tile{border:1px solid #d9dde5;border-radius:8px;padding:.75rem}.tile b{display:block;font-size:1.4rem}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:.35rem .5rem;border-bottom:1px solid #e6e9ef;vertical-align:top}
th{font-weight:600;background:#f6f7f9}td.n{text-align:right;font-variant-numeric:tabular-nums}
</style></head><body>
<h1>GenADB audit report</h1>
<div class="muted">Generated {{.GeneratedAt}}{{if .Source}} from {{.Source}}{{end}}{{if .FirstEvent}} · records {{.FirstEvent}} to {{.LastEvent}}{{end}}</div>
<p>Integrity: {{if .Chain.Valid}}<span class="ok">hash chain intact</span> ({{.Chain.Records}} records{{if .Chain.Anchor}}, anchor {{.Chain.Anchor}}{{end}}){{range .Chain.Warnings}}<br><span class="bad">warning: {{.}}</span>{{end}}{{else}}<span class="bad">hash chain BROKEN at record {{.Chain.BrokenAt}}: {{.Chain.Problem}}</span>{{end}}</p>
<div class="tiles">
<div class="tile"><b>{{.Totals.Sessions}}</b>sessions</div>
<div class="tile"><b>{{.Totals.Operations}}</b>adb operations</div>
<div class="tile"><b>{{.Totals.Denials}}</b>denied attempts</div>
<div class="tile"><b>{{.Totals.Revocations}}</b>revocations</div>
<div class="tile"><b>{{bytes .Totals.BytesUp}}</b>to devices</div>
<div class="tile"><b>{{bytes .Totals.BytesDown}}</b>from devices</div>
</div>
<h2>By user</h2>{{template "groups" .ByUser}}
<h2>By device</h2>{{template "groups" .ByDevice}}
<h2>By operation</h2>{{template "groups" .ByOp}}
<h2>Sessions</h2>
<table><tr><th>Session</th><th>User</th><th>Device</th><th>Path</th><th>Start</th><th>End</th><th>Ops</th><th>Up</th><th>Down</th></tr>
{{range .Sessions}}<tr><td>{{.Session}}</td><td>{{.User}}</td><td>{{.Device}}</td><td>{{.Transport}}</td><td>{{.Start}}</td><td>{{.End}}{{if .EndReason}} ({{.EndReason}}){{end}}</td><td class="n">{{.Operations}}</td><td class="n">{{bytes .BytesUp}}</td><td class="n">{{bytes .BytesDown}}</td></tr>
{{else}}<tr><td colspan="9" class="muted">No sessions in range.</td></tr>{{end}}</table>
<h2>Denied attempts</h2>
<table><tr><th>Time</th><th>User</th><th>Device</th><th>Reason</th></tr>
{{range .Denials}}<tr><td>{{.TS}}</td><td>{{.User}}</td><td>{{.Device}}</td><td>{{.Reason}}</td></tr>
{{else}}<tr><td colspan="4" class="muted">None.</td></tr>{{end}}</table>
</body></html>
{{define "groups"}}<table><tr><th></th><th>Sessions</th><th>Operations</th><th>Denials</th><th>Up</th><th>Down</th></tr>
{{range .}}<tr><td>{{.Key}}</td><td class="n">{{.Sessions}}</td><td class="n">{{.Operations}}</td><td class="n">{{.Denials}}</td><td class="n">{{bytes .BytesUp}}</td><td class="n">{{bytes .BytesDown}}</td></tr>
{{else}}<tr><td colspan="6" class="muted">None.</td></tr>{{end}}</table>{{end}}`))

func writeHTML(w io.Writer, r Report) error { return htmlTmpl.Execute(w, r) }

func humanBytes(n int64) string {
	const k = 1024
	switch {
	case n >= k*k*k:
		return fmt.Sprintf("%.1f GiB", float64(n)/(k*k*k))
	case n >= k*k:
		return fmt.Sprintf("%.1f MiB", float64(n)/(k*k))
	case n >= k:
		return fmt.Sprintf("%.1f KiB", float64(n)/k)
	}
	return fmt.Sprintf("%d B", n)
}

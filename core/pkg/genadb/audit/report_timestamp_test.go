package audit

import "testing"

func TestReportTimestampBoundsUseChronologicalOrder(t *testing.T) {
	events := []Event{
		{"ts": "2026-11-26T10:00:00.5Z"},
		{"ts": "2026-11-26T10:00:00Z"},
		{"ts": "2026-11-26T11:00:00.25+01:00"},
	}
	r := Build(events, Options{})
	if r.FirstEvent != "2026-11-26T10:00:00Z" || r.LastEvent != "2026-11-26T10:00:00.5Z" {
		t.Fatalf("unexpected timestamp bounds: first=%q last=%q", r.FirstEvent, r.LastEvent)
	}
}

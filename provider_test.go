package connbyte

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

// fakeAPI is an in-memory stand-in for the ConnByte /ns API.
type fakeAPI struct {
	mu      sync.Mutex
	zones   map[string]string // id -> zone name
	records map[string][]apiRecord
	nextID  int64
	calls   []string
}

func newFakeAPI(t *testing.T) (*fakeAPI, *Provider) {
	t.Helper()
	f := &fakeAPI{
		zones:   map[string]string{"01ZONEA": "example.com", "01ZONEB": "sub.example.com"},
		records: map[string][]apiRecord{"01ZONEA": {{ID: 1, Name: "example.com", Type: "NS", Content: "ns.connbyte.com", TTL: 86400}}, "01ZONEB": nil},
		nextID:  100,
	}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, &Provider{APIToken: "secret", BaseURL: srv.URL}
}

func (f *fakeAPI) reply(w http.ResponseWriter, code int, data any, field []map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": map[string]any{"code": code, "title": http.StatusText(code), "message": "msg", "logId": "01LOG"},
		"data":   data,
		"field":  field,
	})
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.URL.Path)

	if r.Method != http.MethodPost {
		f.reply(w, 404, nil, nil)
		return
	}
	if r.Header.Get("Authorization") != "Bearer secret" {
		f.reply(w, 400, nil, []map[string]string{{"authorization": "'Authorization' must be set."}})
		return
	}
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	zoneID, _ := body["zoneId"].(string)

	switch r.URL.Path {
	case "/ns/zone/list":
		var out []map[string]any
		for id, name := range f.zones {
			out = append(out, map[string]any{"zone": apiZone{ID: id, ProjectID: "01P", Zone: name}})
		}
		f.reply(w, 200, out, nil)
	case "/ns/record/list":
		var out []map[string]any
		for _, rec := range f.records[zoneID] {
			out = append(out, map[string]any{"record": rec})
		}
		f.reply(w, 200, out, nil)
	case "/ns/record/create":
		name, _ := body["name"].(string)
		if name == "" {
			f.reply(w, 400, nil, []map[string]string{{"name": "Field must not be empty."}})
			return
		}
		fqdn := f.zones[zoneID]
		if name != "@" {
			fqdn = name + "." + fqdn
		}
		content, _ := body["content"].(string)
		typ, _ := body["type"].(string)
		if typ == "TXT" {
			content = `"` + content + `"` // the real backend stores TXT content quoted
		}
		ttl := int(body["ttl"].(float64))
		if ttl < 60 {
			f.reply(w, 400, nil, []map[string]string{{"ttl": "too small"}})
			return
		}
		f.nextID++
		rec := apiRecord{ID: f.nextID, Name: fqdn, Type: typ, Content: content, TTL: ttl, Priority: int(body["priority"].(float64))}
		f.records[zoneID] = append(f.records[zoneID], rec)
		f.reply(w, 200, recordCreated{ID: rec.ID, Record: fqdn}, nil)
	case "/ns/record/delete":
		id := int64(body["recordId"].(float64))
		recs := f.records[zoneID]
		for i, rec := range recs {
			if rec.ID == id {
				f.records[zoneID] = append(recs[:i], recs[i+1:]...)
				f.reply(w, 200, map[string]any{}, nil)
				return
			}
		}
		f.reply(w, 400, nil, []map[string]string{{"recordId": "not found"}})
	default:
		f.reply(w, 404, nil, nil)
	}
}

func rrs(recs []libdns.Record) []string {
	var out []string
	for _, r := range recs {
		rr := r.RR()
		out = append(out, rr.Name+" "+rr.Type+" "+rr.TTL.String()+" "+rr.Data)
	}
	sort.Strings(out)
	return out
}

func TestAppendGetDeleteTXT(t *testing.T) {
	ctx := context.Background()
	f, p := newFakeAPI(t)

	added, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{
		libdns.TXT{Name: "_acme-challenge.www", Text: "token-1", TTL: 120 * time.Second},
		libdns.TXT{Name: "_acme-challenge.www", Text: "token-2", TTL: 120 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 2 {
		t.Fatalf("added %d records", len(added))
	}
	if _, ok := added[0].(libdns.TXT); !ok {
		t.Fatalf("expected libdns.TXT, got %T", added[0])
	}
	if got := f.records["01ZONEA"][1]; got.Name != "_acme-challenge.www.example.com" || got.TTL != 120 {
		t.Fatalf("unexpected stored record %+v", got)
	}

	all, err := p.GetRecords(ctx, "example.com.")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"@ NS 24h0m0s ns.connbyte.com",
		"_acme-challenge.www TXT 2m0s token-1",
		"_acme-challenge.www TXT 2m0s token-2",
	}
	if strings.Join(rrs(all), "|") != strings.Join(want, "|") {
		t.Fatalf("GetRecords = %q, want %q", rrs(all), want)
	}

	deleted, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{libdns.TXT{Name: "_acme-challenge.www", Text: "token-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 {
		t.Fatalf("deleted %d records, want 1", len(deleted))
	}

	// Deleting again is a no-op.
	deleted, err = p.DeleteRecords(ctx, "example.com.", []libdns.Record{libdns.TXT{Name: "_acme-challenge.www", Text: "token-1"}})
	if err != nil || len(deleted) != 0 {
		t.Fatalf("second delete: %v, %d", err, len(deleted))
	}

	if len(f.records["01ZONEA"]) != 2 {
		t.Fatalf("zone has %d records, want 2", len(f.records["01ZONEA"]))
	}
}

func TestZoneMatchingUsesExactZone(t *testing.T) {
	ctx := context.Background()
	f, p := newFakeAPI(t)

	if _, err := p.AppendRecords(ctx, "sub.example.com", []libdns.Record{libdns.TXT{Name: "_acme-challenge", Text: "x"}}); err != nil {
		t.Fatal(err)
	}
	if len(f.records["01ZONEB"]) != 1 || len(f.records["01ZONEA"]) != 1 {
		t.Fatalf("record created in wrong zone: %+v", f.records)
	}
	if f.records["01ZONEB"][0].TTL != 3600 {
		t.Fatalf("default TTL not applied: %d", f.records["01ZONEB"][0].TTL)
	}

	if _, err := p.AppendRecords(ctx, "unknown.org.", []libdns.Record{libdns.TXT{Name: "x", Text: "x"}}); err == nil {
		t.Fatal("expected error for unknown zone")
	}
}

func TestSetRecordsReplacesOnlySameNameAndType(t *testing.T) {
	ctx := context.Background()
	f, p := newFakeAPI(t)

	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{
		libdns.RR{Name: "www", Type: "A", Data: "192.0.2.1", TTL: time.Hour},
		libdns.RR{Name: "www", Type: "A", Data: "192.0.2.2", TTL: time.Hour},
		libdns.TXT{Name: "www", Text: "keep me", TTL: time.Hour},
	}); err != nil {
		t.Fatal(err)
	}

	set, err := p.SetRecords(ctx, "example.com.", []libdns.Record{
		libdns.RR{Name: "www", Type: "A", Data: "192.0.2.2", TTL: time.Hour},
		libdns.RR{Name: "www", Type: "A", Data: "192.0.2.3", TTL: time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 2 {
		t.Fatalf("SetRecords returned %d records, want 2", len(set))
	}

	all, err := p.GetRecords(ctx, "example.com.")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"@ NS 24h0m0s ns.connbyte.com",
		"www A 1h0m0s 192.0.2.2",
		"www A 1h0m0s 192.0.2.3",
		"www TXT 1h0m0s keep me",
	}
	if strings.Join(rrs(all), "|") != strings.Join(want, "|") {
		t.Fatalf("GetRecords = %q, want %q", rrs(all), want)
	}
	_ = f
}

func TestMXPriorityRoundTrip(t *testing.T) {
	ctx := context.Background()
	f, p := newFakeAPI(t)

	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{
		libdns.MX{Name: "@", Preference: 10, Target: "mail.example.com.", TTL: time.Hour},
	}); err != nil {
		t.Fatal(err)
	}
	stored := f.records["01ZONEA"][1]
	if stored.Priority != 10 || stored.Content != "mail.example.com." || stored.Name != "example.com" {
		t.Fatalf("unexpected stored MX %+v", stored)
	}
	all, err := p.GetRecords(ctx, "example.com.")
	if err != nil {
		t.Fatal(err)
	}
	var mx libdns.MX
	for _, r := range all {
		if m, ok := r.(libdns.MX); ok {
			mx = m
		}
	}
	if mx.Preference != 10 || mx.Target != "mail.example.com." || mx.Name != "@" {
		t.Fatalf("unexpected MX %+v", mx)
	}
}

func TestZoneApexNameIsAt(t *testing.T) {
	ctx := context.Background()
	f, p := newFakeAPI(t)

	for _, name := range []string{"@", ""} {
		if _, err := p.AppendRecords(ctx, "sub.example.com.", []libdns.Record{
			libdns.TXT{Name: name, Text: "apex-" + name, TTL: 2 * time.Minute},
		}); err != nil {
			t.Fatalf("name %q: %v", name, err)
		}
	}
	for _, rec := range f.records["01ZONEB"] {
		if rec.Name != "sub.example.com" {
			t.Fatalf("apex record stored as %q", rec.Name)
		}
	}
	deleted, err := p.DeleteRecords(ctx, "sub.example.com.", []libdns.Record{
		libdns.TXT{Name: "@", Text: "apex-@"},
	})
	if err != nil || len(deleted) != 1 || len(f.records["01ZONEB"]) != 1 {
		t.Fatalf("delete apex: deleted=%v err=%v left=%v", deleted, err, f.records["01ZONEB"])
	}
}

func TestErrors(t *testing.T) {
	ctx := context.Background()
	_, p := newFakeAPI(t)

	p.APIToken = "wrong"
	_, err := p.GetRecords(ctx, "example.com.")
	if err == nil || !strings.Contains(err.Error(), "authorization") {
		t.Fatalf("expected API error with field detail, got %v", err)
	}

	p.APIToken = ""
	if _, err := p.GetRecords(ctx, "example.com."); err == nil {
		t.Fatal("expected error for empty token")
	}

	p.APIToken = "secret"
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "x", Type: "CAA", Data: `0 issue "letsencrypt.org"`}}); err == nil {
		t.Fatal("expected error for unsupported type")
	}
}

func TestListZones(t *testing.T) {
	_, p := newFakeAPI(t)
	zones, err := p.ListZones(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, z := range zones {
		names = append(names, z.Name)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "example.com.,sub.example.com." {
		t.Fatalf("zones = %v", names)
	}
}

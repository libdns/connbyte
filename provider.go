// Package connbyte implements a DNS record management client compatible
// with the libdns interfaces for ConnByte (https://connbyte.com/).
//
// It uses the ConnByte DNS API (https://api.connbyte.com/) with a bearer token.
//
// Supported record types are the ones accepted by the ConnByte API:
// A, AAAA, CNAME, MX, NS, SRV and TXT.
//
// The ConnByte API has no batch operations, so SetRecords and DeleteRecords
// are not atomic. If an error occurs part way, some changes may already be
// applied.
package connbyte

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with ConnByte.
type Provider struct {
	// APIToken is the ConnByte API token (required).
	APIToken string `json:"api_token,omitempty"`

	// BaseURL overrides the API endpoint. Optional, defaults to https://api.connbyte.com.
	BaseURL string `json:"base_url,omitempty"`

	// HTTPClient is used for API calls. Optional.
	HTTPClient *http.Client `json:"-"`

	mu sync.Mutex
}

// supportedTypes are the record types the ConnByte API accepts.
var supportedTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "MX": true, "NS": true, "SRV": true, "TXT": true}

// findZone returns the ConnByte zone ID for the given zone name.
func (p *Provider) findZone(ctx context.Context, zone string) (string, error) {
	var zones []struct {
		Zone apiZone `json:"zone"`
	}
	if err := call(ctx, p, "/ns/zone/list", struct{}{}, &zones); err != nil {
		return "", err
	}
	want := normalizeZone(zone)
	for _, z := range zones {
		if normalizeZone(z.Zone.Zone) == want {
			return z.Zone.ID, nil
		}
	}
	return "", fmt.Errorf("connbyte: zone %q not found in account", want)
}

func (p *Provider) listRecords(ctx context.Context, zoneID string) ([]apiRecord, error) {
	var items []struct {
		Record apiRecord `json:"record"`
	}
	if err := call(ctx, p, "/ns/record/list", map[string]string{"zoneId": zoneID}, &items); err != nil {
		return nil, err
	}
	out := make([]apiRecord, 0, len(items))
	for _, it := range items {
		out = append(out, it.Record)
	}
	return out, nil
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	zoneID, err := p.findZone(ctx, zone)
	if err != nil {
		return nil, err
	}
	recs, err := p.listRecords(ctx, zoneID)
	if err != nil {
		return nil, err
	}
	out := make([]libdns.Record, 0, len(recs))
	for _, r := range recs {
		lr, err := toLibdns(r, zone)
		if err != nil {
			return nil, err
		}
		out = append(out, lr)
	}
	return out, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	zoneID, err := p.findZone(ctx, zone)
	if err != nil {
		return nil, err
	}
	return p.appendRecords(ctx, zoneID, zone, records)
}

func (p *Provider) appendRecords(ctx context.Context, zoneID, zone string, records []libdns.Record) ([]libdns.Record, error) {
	created := make([]libdns.Record, 0, len(records))
	for _, rec := range records {
		in, err := fromLibdns(rec, zoneID)
		if err != nil {
			return created, err
		}
		var res recordCreated
		if err := call(ctx, p, "/ns/record/create", in, &res); err != nil {
			return created, err
		}
		lr, err := toLibdns(apiRecord{
			ID:       res.ID,
			Name:     libdns.AbsoluteName(in.Name, normalizeZone(zone)),
			Type:     in.Type,
			Content:  in.Content,
			TTL:      in.TTL,
			Priority: in.Priority,
		}, zone)
		if err != nil {
			return created, err
		}
		created = append(created, lr)
	}
	return created, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// For every (name, type) pair in the input, existing records that are not in the input are deleted.
// It returns the records that were set (kept or created). This operation is not atomic.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	zoneID, err := p.findZone(ctx, zone)
	if err != nil {
		return nil, err
	}
	existing, err := p.listRecords(ctx, zoneID)
	if err != nil {
		return nil, err
	}

	type key struct{ name, typ string }
	wanted := make(map[key][]libdns.RR)
	for _, rec := range records {
		rr := rec.RR()
		k := key{strings.ToLower(libdns.RelativeName(libdns.AbsoluteName(rr.Name, zone), zone)), rr.Type}
		wanted[k] = append(wanted[k], rr)
	}

	var toCreate []libdns.Record
	var set []libdns.Record
	kept := make(map[int]bool)
	for k, rrs := range wanted {
		for _, want := range rrs {
			found := false
			for i, ex := range existing {
				if kept[i] {
					continue
				}
				exl, err := toLibdns(ex, zone)
				if err != nil {
					return nil, err
				}
				exrr := exl.RR()
				if strings.ToLower(exrr.Name) == k.name && exrr.Type == k.typ && exrr.Data == want.Data && exrr.TTL == effectiveTTL(want.TTL) {
					kept[i] = true
					found = true
					set = append(set, exl)
					break
				}
			}
			if !found {
				toCreate = append(toCreate, want)
			}
		}
	}

	for i, ex := range existing {
		if kept[i] {
			continue
		}
		exl, err := toLibdns(ex, zone)
		if err != nil {
			return nil, err
		}
		exrr := exl.RR()
		if _, ok := wanted[key{strings.ToLower(exrr.Name), exrr.Type}]; !ok {
			continue
		}
		if err := call[struct{}](ctx, p, "/ns/record/delete", map[string]any{"zoneId": zoneID, "recordId": ex.ID}, nil); err != nil {
			return nil, err
		}
	}

	created, err := p.appendRecords(ctx, zoneID, zone, toCreate)
	return append(set, created...), err
}

// DeleteRecords deletes the specified records from the zone. It returns the records that were deleted.
// Type, TTL and value may be left empty to match any value. Records that do not exist are ignored.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	zoneID, err := p.findZone(ctx, zone)
	if err != nil {
		return nil, err
	}
	existing, err := p.listRecords(ctx, zoneID)
	if err != nil {
		return nil, err
	}

	var deleted []libdns.Record
	done := make(map[int64]bool)
	for _, rec := range records {
		want := rec.RR()
		wantName := strings.ToLower(libdns.RelativeName(libdns.AbsoluteName(want.Name, zone), zone))
		for _, ex := range existing {
			if done[ex.ID] {
				continue
			}
			exl, err := toLibdns(ex, zone)
			if err != nil {
				return deleted, err
			}
			exrr := exl.RR()
			if strings.ToLower(exrr.Name) != wantName ||
				(want.Type != "" && want.Type != exrr.Type) ||
				(want.TTL != 0 && want.TTL != exrr.TTL) ||
				(want.Data != "" && want.Data != exrr.Data) {
				continue
			}
			if err := call[struct{}](ctx, p, "/ns/record/delete", map[string]any{"zoneId": zoneID, "recordId": ex.ID}, nil); err != nil {
				return deleted, err
			}
			done[ex.ID] = true
			deleted = append(deleted, exl)
		}
	}
	return deleted, nil
}

// ListZones returns the zones of the account.
func (p *Provider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var zones []struct {
		Zone apiZone `json:"zone"`
	}
	if err := call(ctx, p, "/ns/zone/list", struct{}{}, &zones); err != nil {
		return nil, err
	}
	out := make([]libdns.Zone, 0, len(zones))
	for _, z := range zones {
		out = append(out, libdns.Zone{Name: normalizeZone(z.Zone.Zone) + "."})
	}
	return out, nil
}

const (
	minTTL     = 60 * time.Second
	maxTTL     = 86400 * time.Second
	defaultTTL = 3600 * time.Second
)

// effectiveTTL returns the TTL the API will store for the requested TTL.
func effectiveTTL(ttl time.Duration) time.Duration {
	switch {
	case ttl == 0:
		return defaultTTL
	case ttl < minTTL:
		return minTTL
	case ttl > maxTTL:
		return maxTTL
	}
	return ttl.Truncate(time.Second)
}

func normalizeZone(zone string) string {
	return strings.ToLower(strings.TrimSuffix(zone, "."))
}

// fromLibdns converts a libdns record to a ConnByte API create payload.
func fromLibdns(rec libdns.Record, zoneID string) (recordInput, error) {
	rr := rec.RR()
	if !supportedTypes[rr.Type] {
		return recordInput{}, fmt.Errorf("connbyte: record type %q is not supported", rr.Type)
	}
	name := rr.Name
	if name == "@" {
		name = ""
	}
	in := recordInput{
		ZoneID:  zoneID,
		Name:    name,
		Type:    rr.Type,
		Content: rr.Data,
		TTL:     int(effectiveTTL(rr.TTL) / time.Second),
	}
	switch rr.Type {
	case "MX", "SRV":
		// The API stores the MX preference / SRV priority in a separate field.
		prio, rest, ok := strings.Cut(strings.TrimSpace(rr.Data), " ")
		if !ok {
			return recordInput{}, fmt.Errorf("connbyte: invalid %s data %q", rr.Type, rr.Data)
		}
		n, err := strconv.Atoi(prio)
		if err != nil {
			return recordInput{}, fmt.Errorf("connbyte: invalid %s priority %q", rr.Type, prio)
		}
		in.Priority = n
		in.Content = strings.TrimSpace(rest)
	}
	return in, nil
}

// toLibdns converts a ConnByte API record into a typed libdns record relative to zone.
func toLibdns(r apiRecord, zone string) (libdns.Record, error) {
	data := r.Content
	switch r.Type {
	case "TXT":
		data = unquoteTXT(data)
	case "MX", "SRV":
		data = strconv.Itoa(r.Priority) + " " + data
	}
	rr := libdns.RR{
		Name: libdns.RelativeName(strings.TrimSuffix(r.Name, ".")+".", normalizeZone(zone)+"."),
		TTL:  time.Duration(r.TTL) * time.Second,
		Type: r.Type,
		Data: data,
	}
	parsed, err := rr.Parse()
	if err != nil {
		return nil, fmt.Errorf("connbyte: record %d: %w", r.ID, err)
	}
	return parsed, nil
}

// unquoteTXT removes the surrounding quotes some DNS backends add to TXT content.
func unquoteTXT(s string) string {
	if len(s) >= 2 && strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) && !strings.Contains(s[1:len(s)-1], `" "`) {
		if u, err := strconv.Unquote(s); err == nil {
			return u
		}
		return s[1 : len(s)-1]
	}
	return s
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
	_ libdns.ZoneLister     = (*Provider)(nil)
)

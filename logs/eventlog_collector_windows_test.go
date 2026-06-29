//go:build windows

package logs

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/coroot/logparser"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestEventLogCollectorCollectsMetricLabels(t *testing.T) {
	poller := &fakeEventLogPoller{entries: []LogEntry{{
		Timestamp: time.Now(),
		Channel:   "Application",
		Provider:  "CorootTest",
		EventID:   4242,
		Level:     logparser.LevelError,
		Message:   "ERROR coroot event log test line 1",
	}}}
	collector := newEventLogCollector(poller, 10*time.Millisecond)
	defer collector.Close()

	families := waitForEventLogMetric(t, collector, 5*time.Second)
	metric := metricFamily(t, families, "windows_event_log_messages_total")
	if len(metric.Metric) == 0 {
		t.Fatal("windows_event_log_messages_total has no samples")
	}
	assertMetricLabels(t, metric.Metric[0], map[string]string{
		"channel":  "Application",
		"provider": "CorootTest",
		"event_id": "4242",
		"level":    "error",
	})
}

func TestNormalizeEventLogChannels(t *testing.T) {
	got := normalizeEventLogChannels([]string{"Application", " ", "System", "Application"})
	want := []string{"Application", "System"}
	assertChannels(t, got, want)
}

func TestNormalizeEventLogChannelsUsesAvailableChannels(t *testing.T) {
	withAvailableEventLogChannels(t, []string{"Application", "Security", "System", "Application"}, nil)

	got := normalizeEventLogChannels(nil)
	assertChannels(t, got, []string{"Application", "Security", "System"})
}

func TestNormalizeEventLogChannelsFallsBackWhenEnumerationFails(t *testing.T) {
	withAvailableEventLogChannels(t, nil, errors.New("channel enumeration failed"))

	got := normalizeEventLogChannels(nil)
	assertChannels(t, got, []string{"Application", "System", "Security"})
}

func TestShouldDropEventLogEntry(t *testing.T) {
	tests := []struct {
		name string
		in   LogEntry
		want bool
	}{
		{
			name: "security audit success hex",
			in:   LogEntry{Channel: "Security", Keywords: "0x8020000000000000"},
			want: true,
		},
		{
			name: "security audit success text",
			in:   LogEntry{Channel: "Security", Keywords: "Audit Success"},
			want: true,
		},
		{
			name: "security audit failure",
			in:   LogEntry{Channel: "Security", Keywords: "0x8010000000000000"},
			want: false,
		},
		{
			name: "security unknown keyword",
			in:   LogEntry{Channel: "Security"},
			want: false,
		},
		{
			name: "non-security success keyword",
			in:   LogEntry{Channel: "Application", Keywords: "0x8020000000000000"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldDropEventLogEntry(tt.in); got != tt.want {
				t.Fatalf("shouldDropEventLogEntry()=%t, want %t", got, tt.want)
			}
		})
	}
}

func TestParseEventCapturesKeywords(t *testing.T) {
	entry, ok := parseEvent(`<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID><Level>0</Level><TimeCreated SystemTime="2026-06-29T01:02:03Z"/><Execution ProcessID="4"/><Channel>Security</Channel><Keywords>0x8020000000000000</Keywords></System><EventData><Data>ignored</Data></EventData><RenderingInfo><Message>audit success</Message></RenderingInfo></Event>`)
	if !ok {
		t.Fatal("parseEvent returned false")
	}
	if entry.Channel != "Security" || entry.EventID != 4624 || entry.Keywords != "0x8020000000000000" {
		t.Fatalf("parsed entry=%+v", entry)
	}
}

func TestCreateEventLogSubscriptionsUsesCombinedQuery(t *testing.T) {
	var calls [][]string
	subscriptions, err := createEventLogSubscriptions([]string{"Application", "System"}, func(channels []string) (*eventLogSubscription, error) {
		calls = append(calls, append([]string(nil), channels...))
		return &eventLogSubscription{channels: append([]string(nil), channels...)}, nil
	})
	if err != nil {
		t.Fatalf("createEventLogSubscriptions failed: %v", err)
	}
	if len(subscriptions) != 1 {
		t.Fatalf("subscriptions=%d, want 1", len(subscriptions))
	}
	assertChannels(t, calls[0], []string{"Application", "System"})
	assertChannels(t, subscribedEventLogChannels(subscriptions), []string{"Application", "System"})
}

func TestCreateEventLogSubscriptionsFallsBackPerChannel(t *testing.T) {
	var calls [][]string
	combinedErr := errors.New("combined query unsupported")
	subscriptions, err := createEventLogSubscriptions([]string{"Application", "BadChannel", "System"}, func(channels []string) (*eventLogSubscription, error) {
		calls = append(calls, append([]string(nil), channels...))
		if len(channels) > 1 {
			return nil, combinedErr
		}
		if channels[0] == "BadChannel" {
			return nil, errors.New("channel unsupported")
		}
		return &eventLogSubscription{channels: append([]string(nil), channels...)}, nil
	})
	if err != nil {
		t.Fatalf("createEventLogSubscriptions failed: %v", err)
	}
	if len(calls) != 4 {
		t.Fatalf("calls=%v, want combined plus three per-channel calls", calls)
	}
	if len(subscriptions) != 2 {
		t.Fatalf("subscriptions=%d, want 2", len(subscriptions))
	}
	assertChannels(t, subscribedEventLogChannels(subscriptions), []string{"Application", "System"})
}

func TestCreateEventLogSubscriptionsFailsWhenAllChannelsFail(t *testing.T) {
	_, err := createEventLogSubscriptions([]string{"Application", "System"}, func(channels []string) (*eventLogSubscription, error) {
		return nil, errors.New("subscribe failed")
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func assertChannels(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("channels=%v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("channels=%v, want %v", got, want)
		}
	}
}

func withAvailableEventLogChannels(t *testing.T, channels []string, err error) {
	t.Helper()
	old := listAvailableEventLogChannels
	listAvailableEventLogChannels = func() ([]string, error) {
		return channels, err
	}
	t.Cleanup(func() {
		listAvailableEventLogChannels = old
	})
}

func waitForEventLogMetric(t *testing.T, collector *EventLogCollector, timeout time.Duration) []*dto.MetricFamily {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		reg := prometheus.NewRegistry()
		if err := reg.Register(collector); err != nil {
			t.Fatalf("register failed: %v", err)
		}
		families, err := reg.Gather()
		if err != nil {
			t.Fatalf("gather failed: %v", err)
		}
		if family := findMetricFamily(families, "windows_event_log_messages_total"); family != nil && len(family.Metric) > 0 {
			return families
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("windows_event_log_messages_total did not appear within %s", timeout)
	return nil
}

func findMetricFamily(families []*dto.MetricFamily, name string) *dto.MetricFamily {
	for _, family := range families {
		if family.GetName() == name {
			return family
		}
	}
	return nil
}

func metricFamily(t *testing.T, families []*dto.MetricFamily, name string) *dto.MetricFamily {
	t.Helper()
	for _, family := range families {
		if family.GetName() == name {
			return family
		}
	}
	t.Fatalf("metric family %q not found", name)
	return nil
}

func assertMetricLabels(t *testing.T, metric *dto.Metric, expected map[string]string) {
	t.Helper()
	got := map[string]string{}
	for _, label := range metric.Label {
		got[label.GetName()] = label.GetValue()
	}
	for k, v := range expected {
		if got[k] != v {
			t.Fatalf("label %s=%q, want %q; all labels=%v", k, got[k], v, got)
		}
	}
}

type fakeEventLogPoller struct {
	lock    sync.Mutex
	entries []LogEntry
	closed  bool
}

func (p *fakeEventLogPoller) Poll() []LogEntry {
	p.lock.Lock()
	defer p.lock.Unlock()
	entries := p.entries
	p.entries = nil
	return entries
}

func (p *fakeEventLogPoller) Close() {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.closed = true
}

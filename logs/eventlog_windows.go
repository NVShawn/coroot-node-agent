//go:build windows

package logs

import (
	"encoding/xml"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coroot/logparser"
	"github.com/google/winops/winlog"
	"github.com/google/winops/winlog/wevtapi"
	"golang.org/x/sys/windows"
	"k8s.io/klog/v2"
)

const eventLogLocaleEn = 1033

var listAvailableEventLogChannels = winlog.AvailableChannels

type EventLogReader struct {
	mu            sync.Mutex
	buf           []LogEntry
	subscriptions []*eventLogSubscription
	stop          windows.Handle
}

type eventLogSubscription struct {
	config       *winlog.SubscribeConfig
	subscription windows.Handle
	pubCache     map[string]windows.Handle
	channels     []string
}

func NewEventLogReader(channels ...string) (*EventLogReader, error) {
	stop, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}

	subscriptions, err := createEventLogSubscriptions(channels, subscribeEventLogChannels)
	if err != nil {
		windows.CloseHandle(stop)
		return nil, err
	}

	r := &EventLogReader{
		subscriptions: subscriptions,
		stop:          stop,
	}
	activeChannels := subscribedEventLogChannels(subscriptions)
	klog.Infof("subscribed to %d Windows Event Log channels", len(activeChannels))
	klog.V(2).Infof("subscribed to Windows Event Log channels: %v", activeChannels)
	for _, sub := range subscriptions {
		go r.consume(sub)
	}
	return r, nil
}

type eventLogSubscribeFunc func(channels []string) (*eventLogSubscription, error)

func createEventLogSubscriptions(channels []string, subscribe eventLogSubscribeFunc) ([]*eventLogSubscription, error) {
	sub, err := subscribe(channels)
	if err == nil {
		return []*eventLogSubscription{sub}, nil
	}
	if len(channels) <= 1 {
		return nil, err
	}
	klog.Warningf("failed to subscribe to combined Windows Event Log query for %d channels, falling back to per-channel subscriptions: %v", len(channels), err)

	var subscriptions []*eventLogSubscription
	var skipped []string
	for _, channel := range channels {
		sub, err := subscribe([]string{channel})
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", channel, err))
			continue
		}
		subscriptions = append(subscriptions, sub)
	}
	if len(subscriptions) == 0 {
		return nil, fmt.Errorf("failed to subscribe to any Windows Event Log channel after combined query failed: %w", err)
	}
	if len(skipped) > 0 {
		sample := skipped
		if len(sample) > 20 {
			sample = sample[:20]
		}
		klog.Warningf("skipped %d unsupported Windows Event Log channels after per-channel fallback; first %d: %v", len(skipped), len(sample), sample)
	}
	return subscriptions, nil
}

func subscribeEventLogChannels(channels []string) (*eventLogSubscription, error) {
	signal, err := windows.CreateEvent(nil, 1, 1, nil)
	if err != nil {
		return nil, err
	}

	xpaths := make(map[string]string, len(channels))
	for _, ch := range channels {
		xpaths[ch] = "*"
	}
	xmlQuery, err := winlog.BuildStructuredXMLQuery(xpaths)
	if err != nil {
		windows.CloseHandle(signal)
		return nil, err
	}
	queryPtr, err := syscall.UTF16PtrFromString(string(xmlQuery))
	if err != nil {
		windows.CloseHandle(signal)
		return nil, err
	}

	cfg := &winlog.SubscribeConfig{
		SignalEvent: signal,
		Query:       queryPtr,
		Flags:       wevtapi.EvtSubscribeToFutureEvents | wevtapi.EvtSubscribeTolerateQueryErrors,
	}
	subscription, err := winlog.Subscribe(cfg)
	if err != nil {
		cfg.Close()
		return nil, err
	}

	return &eventLogSubscription{
		config:       cfg,
		subscription: subscription,
		pubCache:     map[string]windows.Handle{},
		channels:     append([]string(nil), channels...),
	}, nil
}

func subscribedEventLogChannels(subscriptions []*eventLogSubscription) []string {
	var channels []string
	for _, sub := range subscriptions {
		channels = append(channels, sub.channels...)
	}
	return channels
}

func (r *EventLogReader) consume(sub *eventLogSubscription) {
	handles := []windows.Handle{r.stop, sub.config.SignalEvent}
	for {
		ev, err := windows.WaitForMultipleObjects(handles, false, windows.INFINITE)
		if err != nil || ev == windows.WAIT_OBJECT_0 {
			return
		}
		for {
			events, err := winlog.GetRenderedEvents(sub.config, sub.pubCache, sub.subscription, 64, eventLogLocaleEn)
			for _, x := range events {
				if entry, ok := parseEvent(x); ok {
					r.mu.Lock()
					r.buf = append(r.buf, entry)
					r.mu.Unlock()
				}
			}
			if err != nil {
				break
			}
		}
		windows.ResetEvent(sub.config.SignalEvent)
	}
}

func (r *EventLogReader) Poll() []LogEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	entries := r.buf
	r.buf = nil
	return entries
}

func (r *EventLogReader) Close() {
	windows.SetEvent(r.stop)
	for _, sub := range r.subscriptions {
		if sub.subscription != 0 {
			winlog.Close(sub.subscription)
		}
		for _, h := range sub.pubCache {
			winlog.Close(h)
		}
		sub.config.Close()
	}
	windows.CloseHandle(r.stop)
}

type LogEntry struct {
	Timestamp time.Time
	Channel   string
	Provider  string
	EventID   uint32
	PID       uint32
	Level     logparser.Level
	Keywords  string
	Message   string
}

type renderedEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     uint32 `xml:"EventID"`
		Level       uint64 `xml:"Level"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Execution struct {
			ProcessID uint32 `xml:"ProcessID,attr"`
		} `xml:"Execution"`
		Channel  string `xml:"Channel"`
		Keywords string `xml:"Keywords"`
	} `xml:"System"`
	EventData struct {
		Data []string `xml:"Data"`
	} `xml:"EventData"`
	RenderingInfo struct {
		Message string `xml:"Message"`
	} `xml:"RenderingInfo"`
}

func parseEvent(x string) (LogEntry, bool) {
	var re renderedEvent
	if err := xml.Unmarshal([]byte(x), &re); err != nil {
		return LogEntry{}, false
	}
	msg := strings.TrimSpace(re.RenderingInfo.Message)
	if msg == "" {
		msg = strings.TrimSpace(strings.Join(re.EventData.Data, " "))
	}
	if msg == "" {
		return LogEntry{}, false
	}
	ts, err := time.Parse(time.RFC3339Nano, re.System.TimeCreated.SystemTime)
	if err != nil {
		ts = time.Now()
	}
	return LogEntry{
		Timestamp: ts,
		Channel:   re.System.Channel,
		Provider:  re.System.Provider.Name,
		EventID:   re.System.EventID,
		PID:       re.System.Execution.ProcessID,
		Level:     winLevelToLogparser(re.System.Level),
		Keywords:  strings.TrimSpace(re.System.Keywords),
		Message:   msg,
	}, true
}

func winLevelToLogparser(level uint64) logparser.Level {
	switch level {
	case 1:
		return logparser.LevelCritical
	case 2:
		return logparser.LevelError
	case 3:
		return logparser.LevelWarning
	case 5:
		return logparser.LevelDebug
	default:
		return logparser.LevelInfo
	}
}

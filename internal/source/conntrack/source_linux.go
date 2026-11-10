//go:build linux

package conntrack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	ct "github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"

	"flowaudit/internal/flow"
	"flowaudit/internal/source"
)

const sourceVersion = "ti-mo/conntrack@v0.5.1"

// Source collects Linux Netfilter conntrack events.
type Source struct {
	nodeID             string
	includePreexisting bool
	includeUnreplied   bool
	netlinkReadBuffer  int
	eventQueueSize     int
}

// Options configures the conntrack source.
type Options struct {
	NodeID             string
	IncludePreexisting bool
	IncludeUnreplied   bool
	NetlinkReadBuffer  int
	EventQueueSize     int
}

// New creates a Linux conntrack source.
func New(options Options) (*Source, error) {
	if strings.TrimSpace(options.NodeID) == "" {
		return nil, errors.New("node id is required")
	}
	if options.EventQueueSize <= 0 {
		return nil, errors.New("event queue size must be greater than zero")
	}

	return &Source{
		nodeID:             options.NodeID,
		includePreexisting: options.IncludePreexisting,
		includeUnreplied:   options.IncludeUnreplied,
		netlinkReadBuffer:  options.NetlinkReadBuffer,
		eventQueueSize:     options.EventQueueSize,
	}, nil
}

// Name returns the stable source name.
func (s *Source) Name() string {
	return "conntrack"
}

// Capabilities describes fields exposed by Netfilter conntrack.
func (s *Source) Capabilities() source.Capabilities {
	return source.Capabilities{
		ReplyTuple:  true,
		NAT:         true,
		NATTuples:   false,
		Counters:    true,
		TCPState:    true,
		Zone:        true,
		CaptureGaps: true,
	}
}

// Check verifies that the current process can query Netfilter conntrack.
func (s *Source) Check(ctx context.Context) error {
	conn, err := ct.Dial(nil)
	if err != nil {
		return fmt.Errorf("dial conntrack netlink: %w", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if _, err := conn.StatsGlobal(); err != nil {
		return fmt.Errorf("query conntrack statistics: %w", err)
	}

	return nil
}

// Run starts collecting events until the context is canceled.
func (s *Source) Run(ctx context.Context, output chan<- flow.Event) error {
	localIPs, err := localAddresses()
	if err != nil {
		return fmt.Errorf("list local addresses: %w", err)
	}
	netnsID := currentNetNSID()

	eventConn, err := ct.Dial(nil)
	if err != nil {
		return fmt.Errorf("open conntrack event connection: %w", err)
	}
	dumpConn, err := ct.Dial(nil)
	if err != nil {
		_ = eventConn.Close()
		return fmt.Errorf("open conntrack dump connection: %w", err)
	}
	defer func() {
		_ = dumpConn.Close()
	}()

	if s.netlinkReadBuffer > 0 {
		if err := eventConn.SetReadBuffer(s.netlinkReadBuffer); err != nil {
			_ = eventConn.Close()
			return fmt.Errorf("set conntrack event read buffer: %w", err)
		}
	}

	rawEvents := make(chan ct.Event, s.eventQueueSize)
	// Subscribe before dumping so changes during the dump are buffered.
	eventErrors, err := eventConn.Listen(rawEvents, 1, netfilter.GroupsCT)
	if err != nil {
		_ = eventConn.Close()
		return fmt.Errorf("listen for conntrack events: %w", err)
	}

	activeClose := true
	defer func() {
		if activeClose {
			closeConntrackConnection(eventConn, rawEvents, eventErrors)
		}
	}()

	if s.includePreexisting {
		// Imported entries are marked preexisting by convertFlow.
		existing, err := dumpConn.Dump(nil)
		if err != nil {
			return fmt.Errorf("dump existing conntrack entries: %w", err)
		}
		for _, item := range existing {
			event, supported, err := safeConvertFlow(
				flow.EventTypeImport,
				item,
				s.convertOptions(localIPs, netnsID),
				time.Now(),
			)
			if err != nil {
				return fmt.Errorf("convert existing conntrack entry: %w", err)
			}
			if supported && !sendEvent(ctx, output, event) {
				return context.Canceled
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			closeConntrackConnection(eventConn, rawEvents, eventErrors)
			activeClose = false
			return nil
		case err := <-eventErrors:
			if err == nil {
				continue
			}
			return fmt.Errorf("receive conntrack event: %w", err)
		case raw, ok := <-rawEvents:
			if !ok {
				return errors.New("conntrack event channel closed")
			}
			if raw.Flow == nil {
				continue
			}

			var eventType flow.EventType
			switch raw.Type {
			case ct.EventNew:
				eventType = flow.EventTypeNew
			case ct.EventUpdate:
				eventType = flow.EventTypeUpdate
			case ct.EventDestroy:
				eventType = flow.EventTypeDestroy
			default:
				continue
			}
			event, supported, err := safeConvertFlow(
				eventType,
				*raw.Flow,
				s.convertOptions(localIPs, netnsID),
				time.Now(),
			)
			if err != nil {
				return fmt.Errorf("convert conntrack event: %w", err)
			}
			if supported && !sendEvent(ctx, output, event) {
				return context.Canceled
			}
		}
	}
}

// convertOptions returns conversion metadata shared by all source events.
func (s *Source) convertOptions(localIPs map[netip.Addr]struct{}, netnsID uint64) convertOptions {
	return convertOptions{
		NodeID:           s.nodeID,
		SourceVersion:    sourceVersion,
		LocalIPs:         localIPs,
		NetNSID:          netnsID,
		IncludeUnreplied: s.includeUnreplied,
	}
}

// localAddresses collects current interface addresses for direction detection.
func localAddresses() (map[netip.Addr]struct{}, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	result := make(map[netip.Addr]struct{})
	for _, item := range interfaces {
		addresses, err := item.Addrs()
		if err != nil {
			return nil, fmt.Errorf("list addresses for %s: %w", item.Name, err)
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				continue
			}
			result[prefix.Addr().Unmap()] = struct{}{}
		}
	}

	return result, nil
}

// currentNetNSID returns the inode-style identifier of the current netns.
func currentNetNSID() uint64 {
	target, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return 0
	}
	start := strings.IndexByte(target, '[')
	end := strings.IndexByte(target, ']')
	if start < 0 || end <= start {
		return 0
	}
	value, err := strconv.ParseUint(target[start+1:end], 10, 64)
	if err != nil {
		return 0
	}

	return value
}

// sendEvent forwards an event unless the collector is shutting down.
func sendEvent(ctx context.Context, output chan<- flow.Event, event flow.Event) bool {
	select {
	case <-ctx.Done():
		return false
	case output <- event:
		return true
	}
}

// closeConntrackConnection closes a listener while draining worker channels.
// Draining prevents library workers from blocking forever during shutdown.
func closeConntrackConnection(
	conn *ct.Conn,
	events <-chan ct.Event,
	errors <-chan error,
) {
	done := make(chan struct{})
	go func() {
		_ = conn.Close()
		close(done)
	}()

	eventChannel := events
	errorChannel := errors
	for eventChannel != nil || errorChannel != nil {
		select {
		case _, ok := <-eventChannel:
			if !ok {
				eventChannel = nil
			}
			continue
		case _, ok := <-errorChannel:
			if !ok {
				errorChannel = nil
			}
			continue
		case <-done:
			return
		}
	}
}

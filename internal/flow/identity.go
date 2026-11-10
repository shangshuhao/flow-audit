package flow

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// NewEventID returns a cryptographically random identifier for an event.
func NewEventID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate event id: %w", err)
	}

	return hex.EncodeToString(value[:]), nil
}

// BuildFlowID returns a deterministic identifier for a newly observed flow.
func BuildFlowID(
	nodeID string,
	source string,
	netnsID uint64,
	zone uint16,
	protocol Protocol,
	original Tuple,
	firstSeen time.Time,
) string {
	key := fmt.Sprintf(
		"%s|%s|%d|%d|%s|%s|%d|%s|%d|%d",
		nodeID,
		source,
		netnsID,
		zone,
		protocol,
		original.SourceIP,
		original.SourcePort,
		original.DestinationIP,
		original.DestinationPort,
		firstSeen.UTC().UnixNano(),
	)
	sum := sha256.Sum256([]byte(key))

	return hex.EncodeToString(sum[:16])
}

// ActiveKey identifies an open flow tuple for event correlation.
func ActiveKey(
	nodeID string,
	source string,
	netnsID uint64,
	zone uint16,
	protocol Protocol,
	original Tuple,
) string {
	return fmt.Sprintf(
		"%s|%s|%d|%d|%s|%s|%d|%s|%d",
		nodeID,
		source,
		netnsID,
		zone,
		protocol,
		original.SourceIP,
		original.SourcePort,
		original.DestinationIP,
		original.DestinationPort,
	)
}

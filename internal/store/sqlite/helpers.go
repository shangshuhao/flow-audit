package sqlite

import "net/netip"

// nullableIP converts an invalid address into a SQL NULL value.
func nullableIP(addr netip.Addr) any {
	if !addr.IsValid() {
		return nil
	}

	return addr.Unmap().String()
}

// nullablePort converts an absent port into a SQL NULL value.
func nullablePort(valid bool, port uint16) any {
	if !valid {
		return nil
	}

	return port
}

// nullableString converts an absent string into a SQL NULL value.
func nullableString(value string) any {
	if value == "" {
		return nil
	}

	return value
}

// boolInt converts a boolean to SQLite's integer representation.
func boolInt(value bool) int {
	if value {
		return 1
	}

	return 0
}

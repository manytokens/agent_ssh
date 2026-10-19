package telemetry

import "strings"

// Classify preserves unknown and ambiguous OpenSSH failures rather than
// confusing server policy rejection with a busy port.
func Classify(text string) string {
	s := strings.ToLower(text)
	switch {
	case s == "":
		return ""
	case strings.Contains(s, "remote host identification has changed"), strings.Contains(s, "host key verification failed"), strings.Contains(s, "host key has changed"):
		return "host_key_verification"
	case strings.Contains(s, "permission denied"), strings.Contains(s, "authentication failed"), strings.Contains(s, "no supported authentication"):
		return "authentication_rejected"
	case strings.Contains(s, "address already in use"):
		return "port_in_use"
	case strings.Contains(s, "remote port forwarding failed"), strings.Contains(s, "administratively prohibited"):
		return "forwarding_rejected"
	case strings.Contains(s, "could not resolve hostname"), strings.Contains(s, "name or service not known"):
		return "dns_failure"
	case strings.Contains(s, "timed out"), strings.Contains(s, "timeout"):
		return "timeout"
	case strings.Contains(s, "connection refused"), strings.Contains(s, "no route to host"), strings.Contains(s, "network is unreachable"):
		return "network_unreachable"
	case strings.Contains(s, "connection reset"), strings.Contains(s, "broken pipe"), strings.Contains(s, "connection closed"):
		return "connection_lost"
	default:
		return "ssh_error"
	}
}

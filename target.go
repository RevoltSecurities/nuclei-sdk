package nucleisdk

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// TargetsFromFile reads targets from a file, one per line.
// Empty lines and lines starting with # are skipped.
func TargetsFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening target file: %w", err)
	}
	defer f.Close()
	return TargetsFromReader(f)
}

// TargetsFromReader reads targets from an io.Reader, one per line.
// Empty lines and lines starting with # are skipped.
func TargetsFromReader(reader io.Reader) ([]string, error) {
	var targets []string
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading targets: %w", err)
	}
	return targets, nil
}

// TargetsFromCIDR expands a CIDR notation into individual IP targets.
func TargetsFromCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parsing CIDR: %w", err)
	}

	var targets []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		targets = append(targets, ip.String())
	}

	// Remove network and broadcast addresses for /31 and larger
	if len(targets) > 2 {
		targets = targets[1 : len(targets)-1]
	}

	return targets, nil
}

// incrementIP increments an IP address by one.
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// TargetsFromCIDRs expands multiple CIDR notations into individual IP targets.
func TargetsFromCIDRs(cidrs []string) ([]string, error) {
	var allTargets []string
	for _, cidr := range cidrs {
		targets, err := TargetsFromCIDR(cidr)
		if err != nil {
			return nil, err
		}
		allTargets = append(allTargets, targets...)
	}
	return allTargets, nil
}

// IPRange generates a list of IPs from a start to end IP (inclusive).
func IPRange(startIP, endIP string) ([]string, error) {
	start := net.ParseIP(startIP).To4()
	end := net.ParseIP(endIP).To4()
	if start == nil || end == nil {
		return nil, fmt.Errorf("invalid IP range: %s - %s", startIP, endIP)
	}

	startInt := binary.BigEndian.Uint32(start)
	endInt := binary.BigEndian.Uint32(end)
	if startInt > endInt {
		return nil, fmt.Errorf("start IP must be less than end IP")
	}

	var targets []string
	for i := startInt; i <= endInt; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		targets = append(targets, ip.String())
	}
	return targets, nil
}

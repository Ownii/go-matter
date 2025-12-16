package discovery

import (
	"context"
)

// ServiceType represents the type of Matter service (Commissionable, Operational).
type ServiceType string

const (
	Commissionable ServiceType = "_matterc._udp"
	Operational    ServiceType = "_matter._tcp"
)

// Advertiser handles announcing the device's presence via mDNS.
type Advertiser struct {
	// TODO: Add mDNS server instance
}

// NewAdvertiser creates a new Advertiser.
func NewAdvertiser() *Advertiser {
	return &Advertiser{}
}

// Advertise starts advertising the specified service.
func (a *Advertiser) Advertise(serviceType ServiceType, port int, txtRecords map[string]string) error {
	// TODO: Implement mDNS advertising
	return nil
}

// Stop stops advertising.
func (a *Advertiser) Stop() error {
	// TODO: Implement stop logic
	return nil
}

// Browser handles discovering other Matter devices.
type Browser struct {
	// TODO: Add mDNS client instance
}

// NewBrowser creates a new Browser.
func NewBrowser() *Browser {
	return &Browser{}
}

// Browse searches for devices offering the specified service.
func (b *Browser) Browse(ctx context.Context, serviceType ServiceType) (<-chan *DiscoveredDevice, error) {
	// TODO: Implement mDNS browsing
	return nil, nil
}

// DiscoveredDevice represents a device found via mDNS.
type DiscoveredDevice struct {
	IPs  []string
	Port int
	Txt  map[string]string
}

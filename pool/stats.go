package pool

import (
	"time"

	"github.com/wyattanderson/arden"
)

// Stats is a point-in-time, internally consistent pool snapshot.
type Stats struct {
	Connections int
	InFlight    int
	Waiters     int
	Dialing     int
	Closing     bool
	Endpoints   []EndpointStats
}

// EndpointStats describes one configured endpoint without exposing setup
// profile or authentication data.
type EndpointStats struct {
	Endpoint    arden.EndpointID
	Address     string
	Healthy     bool
	Connections int
	InFlight    int
	Leases      int
	Dialing     int
	Waiters     int
	Failures    uint64
}

// ConnectionStats describes the admission state of one live connection.
type ConnectionStats struct {
	Endpoint   arden.EndpointID
	Connection uint64
	InFlight   int
	Leased     bool
	Draining   bool
	Age        time.Duration
	IdleFor    time.Duration
}

// ConnectionStats returns a snapshot of live and gracefully draining connection
// state. Broken connections are omitted.
func (p *Pool[P]) ConnectionStats() []ConnectionStats {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	var result []ConnectionStats
	for _, endpoint := range p.order {
		for _, connection := range endpoint.connections {
			if connection.broken {
				continue
			}
			result = append(result, ConnectionStats{
				Endpoint:   endpoint.config.Endpoint.ID,
				Connection: connection.conn.ID(),
				InFlight:   connection.inFlight,
				Leased:     connection.leased,
				Draining:   connection.draining,
				Age:        now.Sub(connection.created),
				IdleFor:    now.Sub(connection.lastIdle),
			})
		}
	}
	return result
}

// Stats returns pool, endpoint, admission, and health counters without
// blocking on network activity.
func (p *Pool[P]) Stats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := Stats{Waiters: p.waiters, Closing: p.closing}
	for _, endpoint := range p.order {
		stats := EndpointStats{
			Endpoint: endpoint.config.Endpoint.ID,
			Address:  endpoint.config.Endpoint.Address,
			Dialing:  endpoint.dialing,
			Waiters:  endpoint.waiters,
			Failures: endpoint.failures,
		}
		result.Dialing += endpoint.dialing
		for _, connection := range endpoint.connections {
			if connection.broken {
				continue
			}
			stats.Connections++
			stats.InFlight += connection.inFlight
			if connection.leased {
				stats.Leases++
			}
		}
		stats.Healthy = stats.Connections != 0
		result.Connections += stats.Connections
		result.InFlight += stats.InFlight
		result.Endpoints = append(result.Endpoints, stats)
	}
	return result
}

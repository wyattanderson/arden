package pool

import (
	"errors"
	"time"
)

const (
	defaultMaxConnectionsPerEndpoint = 2
	defaultMaxInFlightPerConnection  = 8
	defaultMaxWaiters                = 128
	defaultIdleLifetime              = 5 * time.Minute
	defaultMaximumLifetime           = 30 * time.Minute
	defaultShutdownTimeout           = 5 * time.Second
	defaultBackoffInitial            = 100 * time.Millisecond
	defaultBackoffMaximum            = 30 * time.Second
	defaultBackoffJitter             = 0.20
)

// Options contains bounded pool admission and lifecycle policy. Zero fields
// select conservative defaults; zero never means unbounded.
type Options struct {
	MaxConnectionsPerEndpoint int
	MaxInFlightPerConnection  int
	MaxWaiters                int
	IdleLifetime              time.Duration
	MaximumLifetime           time.Duration
	ShutdownTimeout           time.Duration
	BackoffInitial            time.Duration
	BackoffMaximum            time.Duration
	BackoffJitter             float64
}

// DefaultOptions returns the preliminary Phase 6 defaults. The multiplexing
// and admission defaults are deliberately conservative and remain public so
// deployments can tune them from representative 389 DS measurements.
func DefaultOptions() Options {
	return Options{
		MaxConnectionsPerEndpoint: defaultMaxConnectionsPerEndpoint,
		MaxInFlightPerConnection:  defaultMaxInFlightPerConnection,
		MaxWaiters:                defaultMaxWaiters,
		IdleLifetime:              defaultIdleLifetime,
		MaximumLifetime:           defaultMaximumLifetime,
		ShutdownTimeout:           defaultShutdownTimeout,
		BackoffInitial:            defaultBackoffInitial,
		BackoffMaximum:            defaultBackoffMaximum,
		BackoffJitter:             defaultBackoffJitter,
	}
}

// Validate checks options after applying defaults to zero fields.
func (o Options) Validate() error {
	_, err := o.normalized()
	return err
}

func (o Options) normalized() (Options, error) {
	defaults := DefaultOptions()
	if o.MaxConnectionsPerEndpoint == 0 {
		o.MaxConnectionsPerEndpoint = defaults.MaxConnectionsPerEndpoint
	}
	if o.MaxInFlightPerConnection == 0 {
		o.MaxInFlightPerConnection = defaults.MaxInFlightPerConnection
	}
	if o.MaxWaiters == 0 {
		o.MaxWaiters = defaults.MaxWaiters
	}
	if o.IdleLifetime == 0 {
		o.IdleLifetime = defaults.IdleLifetime
	}
	if o.MaximumLifetime == 0 {
		o.MaximumLifetime = defaults.MaximumLifetime
	}
	if o.ShutdownTimeout == 0 {
		o.ShutdownTimeout = defaults.ShutdownTimeout
	}
	if o.BackoffInitial == 0 {
		o.BackoffInitial = defaults.BackoffInitial
	}
	if o.BackoffMaximum == 0 {
		o.BackoffMaximum = defaults.BackoffMaximum
	}
	if o.BackoffJitter == 0 {
		o.BackoffJitter = defaults.BackoffJitter
	}
	switch {
	case o.MaxConnectionsPerEndpoint < 0:
		return Options{}, errors.New("pool: MaxConnectionsPerEndpoint must be positive")
	case o.MaxInFlightPerConnection < 0:
		return Options{}, errors.New("pool: MaxInFlightPerConnection must be positive")
	case o.MaxWaiters < 0:
		return Options{}, errors.New("pool: MaxWaiters must be positive")
	case o.IdleLifetime < 0:
		return Options{}, errors.New("pool: IdleLifetime must be positive")
	case o.MaximumLifetime < 0:
		return Options{}, errors.New("pool: MaximumLifetime must be positive")
	case o.ShutdownTimeout < 0:
		return Options{}, errors.New("pool: ShutdownTimeout must be positive")
	case o.BackoffInitial < 0:
		return Options{}, errors.New("pool: BackoffInitial must be positive")
	case o.BackoffMaximum < 0:
		return Options{}, errors.New("pool: BackoffMaximum must be positive")
	case o.BackoffMaximum < o.BackoffInitial:
		return Options{}, errors.New("pool: BackoffMaximum must not be less than BackoffInitial")
	case o.BackoffJitter < 0 || o.BackoffJitter > 1:
		return Options{}, errors.New("pool: BackoffJitter must be between zero and one")
	}
	return o, nil
}

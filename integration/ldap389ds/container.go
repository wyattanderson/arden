// Package ldap389ds provides a ready-to-use 389 Directory Server container for
// integration tests.
package ldap389ds

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	ldapsPort                  = "3636/tcp"
	defaultServerName          = "arden-389ds.test"
	defaultDirectoryManagerDN  = "cn=Directory Manager"
	directoryManagerPasswordID = "DS_DM_PASSWORD"
	caCertificatePath          = "/data/config/ca.crt"
)

// Container is a 389 Directory Server container configured for LDAPS tests.
type Container struct {
	testcontainers.Container

	address                  string
	tlsConfig                *tls.Config
	serverName               string
	directoryManagerDN       string
	directoryManagerPassword string
}

// Run starts a 389 Directory Server container. The returned container is ready
// for an authenticated LDAPS Directory Manager bind.
func Run(ctx context.Context, image string, opts ...testcontainers.ContainerCustomizer) (*Container, error) {
	password, err := randomPassword()
	if err != nil {
		return nil, fmt.Errorf("generate directory manager password: %w", err)
	}

	containerOptions := []testcontainers.ContainerCustomizer{
		testcontainers.WithConfigModifier(func(config *container.Config) {
			config.Hostname = defaultServerName
		}),
		testcontainers.WithEnv(map[string]string{
			directoryManagerPasswordID: password,
			"LDAPTLS_CACERT":           caCertificatePath,
		}),
		testcontainers.WithExposedPorts(ldapsPort),
		testcontainers.WithWaitStrategyAndDeadline(90*time.Second,
			wait.ForListeningPort(ldapsPort),
			wait.ForExec([]string{
				"ldapwhoami",
				"-x",
				"-H", "ldaps://" + defaultServerName + ":3636",
				"-D", defaultDirectoryManagerDN,
				"-w", password,
			}),
		),
	}
	containerOptions = append(containerOptions, opts...)

	ctr, err := testcontainers.Run(ctx, image, containerOptions...)
	if ctr == nil {
		if err == nil {
			return nil, fmt.Errorf("start 389ds container: no container returned")
		}
		return nil, fmt.Errorf("start 389ds container: %w", err)
	}

	result := &Container{
		Container:                ctr,
		serverName:               defaultServerName,
		directoryManagerDN:       defaultDirectoryManagerDN,
		directoryManagerPassword: password,
	}
	if err != nil {
		return result, fmt.Errorf("start 389ds container: %w", err)
	}

	if err := result.configureClient(ctx); err != nil {
		return result, err
	}
	return result, nil
}

// Address returns the container's mapped LDAPS address.
func (c *Container) Address() string { return c.address }

// TLSConfig returns a configuration that trusts the container's generated CA.
func (c *Container) TLSConfig() *tls.Config { return c.tlsConfig.Clone() }

// ServerName returns the name in the container's generated TLS certificate.
func (c *Container) ServerName() string { return c.serverName }

// DirectoryManagerDN returns the distinguished name for the default Directory
// Manager account.
func (c *Container) DirectoryManagerDN() string { return c.directoryManagerDN }

// DirectoryManagerPassword returns the generated password for the default
// Directory Manager account.
func (c *Container) DirectoryManagerPassword() string { return c.directoryManagerPassword }

func (c *Container) configureClient(ctx context.Context) error {
	caCertificate, err := c.copyCACertificate(ctx)
	if err != nil {
		return err
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caCertificate) {
		return fmt.Errorf("read 389ds CA certificate: invalid PEM")
	}
	c.tlsConfig = &tls.Config{RootCAs: roots}

	host, err := c.Host(ctx)
	if err != nil {
		return fmt.Errorf("get 389ds container host: %w", err)
	}
	port, err := c.MappedPort(ctx, ldapsPort)
	if err != nil {
		return fmt.Errorf("get 389ds LDAPS port: %w", err)
	}
	c.address = net.JoinHostPort(host, port.Port())

	return nil
}

func (c *Container) copyCACertificate(ctx context.Context) ([]byte, error) {
	reader, err := c.CopyFileFromContainer(ctx, caCertificatePath)
	if err != nil {
		return nil, fmt.Errorf("copy 389ds CA certificate: %w", err)
	}
	defer reader.Close()

	certificate, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read 389ds CA certificate: %w", err)
	}
	return certificate, nil
}

func randomPassword() (string, error) {
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

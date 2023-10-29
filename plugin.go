package tls

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/roadrunner-server/tls/v4/acme"
	localTLS "github.com/roadrunner-server/tls/v4/tls"
	"go.uber.org/zap"
)

const (
	pluginName string = "TLS"
)

type Plugin struct {
}

func Init() error {
	return nil
}

func (p *Plugin) Name() string {
	return pluginName
}

func (p *Plugin) TLSConfigWithLE(
	cacheDir, email, challengeType string,
	domains []string, useProduction bool,
	altHTTPPort, altTLSAlpnPort int,
	log *zap.Logger) (*tls.Config, error) {
	return acme.IssueLECertificates(cacheDir, email, challengeType, domains, useProduction, altHTTPPort, altTLSAlpnPort, log)
}

func (p *Plugin) CertPool(rootCa string) (*x509.CertPool, error) {
	return localTLS.CertPool(rootCa)
}

func (p *Plugin) NewTLSConfig() *tls.Config {
	return localTLS.InitTLSConfig()
}

func (p *Plugin) TLSConfWithRootCA(
	certPath, keyPath, rootCAPath string,
	clientAuthType tls.ClientAuthType) (*tls.Config, error) {
	return localTLS.ConfigWithRootCA(certPath, keyPath, rootCAPath, clientAuthType)
}

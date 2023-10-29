package tls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
)

func ConfigWithRootCA(certPath, keyPath, rootCA string, clientAuthType tls.ClientAuthType) (*tls.Config, error) {
	var cert tls.Certificate
	var certPool *x509.CertPool
	var rca []byte
	var err error

	tlsConf := InitTLSConfig()

	// if client CA is not empty we combine it with Cert and Key
	switch {
	case rootCA != "":
		cert, err = tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}

		certPool, err = x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		if certPool == nil {
			certPool = x509.NewCertPool()
		}

		rca, err = os.ReadFile(rootCA)
		if err != nil {
			return nil, err
		}

		if ok := certPool.AppendCertsFromPEM(rca); !ok {
			return nil, errors.New("could not append Certs from PEM")
		}

		tlsConf.ClientAuth = clientAuthType
		tlsConf.ClientCAs = certPool
		tlsConf.Certificates = []tls.Certificate{cert}

		return tlsConf, nil
	default:
		cert, err = tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}

		tlsConf.Certificates = []tls.Certificate{cert}
		// regular TLS from the cert+key
		return tlsConf, nil
	}
}

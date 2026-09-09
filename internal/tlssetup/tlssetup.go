// Package tlssetup provides the control plane's HTTPS termination (D6):
// self-signed dev certificates on 127.0.0.1 in dev mode, or ACME
// (TLS-ALPN-01 via autocert) in production on :443.
package tlssetup

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// DevCertificate holds the generated dev cert material.
type DevCertificate struct {
	CertPEM     []byte
	KeyPEM      []byte
	Fingerprint string // SHA-256 of the DER cert, hex
}

// TLSConfig returns HTTP(S) serving config for the bastion.
func TLSConfig(cfg Config) (*tls.Config, *DevCertificate, error) {
	if cfg.Dev {
		dev, err := EnsureDevCert(cfg.DataDir)
		if err != nil {
			return nil, nil, err
		}
		return &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{dev.Cert},
		}, dev.Info, nil
	}
	m := autocert.Manager{
		Cache:      autocert.DirCache(filepath.Join(cfg.DataDir, "tls", "cache")),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.Hostname),
	}
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: m.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1", "acme-tls/1"}, // TLS-ALPN-01 unfortunately must be on :443
	}, nil, nil
}

// Config carries the TLS choices.
type Config struct {
	Dev      bool   // self-signed loopback cert
	Hostname string // ACME cert name
	DataDir  string
}

// DevResult is the loaded or generated dev certificate.
type DevResult struct {
	Cert tls.Certificate
	Info *DevCertificate
}

// EnsureDevCert loads the dev cert from dataDir/tls or generates a new
// self-signed one bound to 127.0.0.1/localhost (loopback-only, D6).
func EnsureDevCert(dataDir string) (*DevResult, error) {
	dir := filepath.Join(dataDir, "tls")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		der, err2 := os.ReadFile(certPath)
		fp := ""
		if err2 == nil {
			fp = fingerprintPEM(der)
		}
		return &DevResult{Cert: cert, Info: &DevCertificate{Fingerprint: fp}}, nil
	}
	// generate
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "entrance-dev"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "entrance.local"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	slog.Info("generated self-signed dev certificate",
		"fingerprint", fingerprintPEM(certPEM), "path", certPath)
	return &DevResult{
		Cert: cert,
		Info: &DevCertificate{
			CertPEM: certPEM, KeyPEM: keyPEM,
			Fingerprint: fingerprintPEM(certPEM),
		},
	}, nil
}

func fingerprintPEM(certPEM []byte) string {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return ""
	}
	sum := sha256.Sum256(block.Bytes)
	return strings.ToLower(hex.EncodeToString(sum[:]))
}

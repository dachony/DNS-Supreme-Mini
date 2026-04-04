package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"time"
)

// CertRequest contains all fields for generating a self-signed certificate
type CertRequest struct {
	CommonName         string   `json:"common_name"`
	Organization       string   `json:"organization"`
	OrganizationalUnit string   `json:"organizational_unit"`
	Country            string   `json:"country"`
	State              string   `json:"state"`
	Locality           string   `json:"locality"`
	DNSNames           []string `json:"dns_names"`
	ValidityDays       int      `json:"validity_days"`
}

func LoadOrGenerateTLS(certFile, keyFile string) (*tls.Config, error) {
	// Try to load existing cert
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err == nil {
			slog.Info("loaded certificate", "component", "tls", "cert_file", certFile)
			return &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}, nil
		}
	}

	// Generate self-signed
	slog.Info("generating self-signed certificate", "component", "tls")
	cert, err := generateSelfSigned()
	if err != nil {
		return nil, fmt.Errorf("failed to generate self-signed cert: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func generateSelfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"DNS-supreme"},
			CommonName:   "dns-supreme",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "dns-supreme"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func GenerateAndSave(certFile, keyFile string, req *CertRequest) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	// Build subject from request
	subject := pkix.Name{
		CommonName: "dns-supreme",
	}
	if req != nil {
		if req.CommonName != "" {
			subject.CommonName = req.CommonName
		}
		if req.Organization != "" {
			subject.Organization = []string{req.Organization}
		}
		if req.OrganizationalUnit != "" {
			subject.OrganizationalUnit = []string{req.OrganizationalUnit}
		}
		if req.Country != "" {
			subject.Country = []string{req.Country}
		}
		if req.State != "" {
			subject.Province = []string{req.State}
		}
		if req.Locality != "" {
			subject.Locality = []string{req.Locality}
		}
	}

	validityDays := 365
	if req != nil && req.ValidityDays > 0 && req.ValidityDays <= 3650 {
		validityDays = req.ValidityDays
	}

	var dnsNames []string
	if req != nil && len(req.DNSNames) > 0 {
		dnsNames = req.DNSNames
	} else {
		dnsNames = []string{subject.CommonName}
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(validityDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}

	os.MkdirAll(fmt.Sprintf("%s", certFile[:len(certFile)-len("/server.crt")]), 0755)

	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	keyOut.Close()

	slog.Info("self-signed certificate generated", "component", "certs", "cn", subject.CommonName, "validity_days", validityDays, "sans", dnsNames)
	return nil
}

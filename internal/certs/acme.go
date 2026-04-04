package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

// ACMEConfig holds ACME/Let's Encrypt configuration
type ACMEConfig struct {
	Provider       string `json:"provider"`        // "letsencrypt", "letsencrypt-staging", "zerossl", "custom"
	Email          string `json:"email"`
	URL            string `json:"url"`             // custom ACME directory URL
	Challenge      string `json:"challenge"`       // "dns-01" or "http-01"
	DNSProvider    string `json:"dns_provider"`    // "local" (DNS Supreme zones), "cloudflare"
	CloudflareToken string `json:"cloudflare_token"` // Cloudflare API token for DNS-01
}

// ACMEClient handles certificate requests via ACME protocol
type ACMEClient struct {
	cfg        ACMEConfig
	certDir    string
	dnsSetFunc func(fqdn, value string) error // function to set DNS TXT record for dns-01
	dnsClearFunc func(fqdn string) error       // function to clear DNS TXT record
	mu         sync.Mutex
}

func NewACMEClient(certDir string) *ACMEClient {
	return &ACMEClient{
		certDir: certDir,
		cfg: ACMEConfig{
			Provider:  "letsencrypt",
			Challenge: "dns-01",
		},
	}
}

func (a *ACMEClient) GetConfig() ACMEConfig {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg
}

func (a *ACMEClient) SetConfig(cfg ACMEConfig) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cfg = cfg
}

// SetDNSSolver sets the functions used to create/remove DNS TXT records for dns-01 challenges
func (a *ACMEClient) SetDNSSolver(setFn func(fqdn, value string) error, clearFn func(fqdn string) error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.dnsSetFunc = setFn
	a.dnsClearFunc = clearFn
}

func (a *ACMEClient) directoryURL() string {
	switch a.cfg.Provider {
	case "letsencrypt":
		return "https://acme-v02.api.letsencrypt.org/directory"
	case "letsencrypt-staging":
		return "https://acme-staging-v02.api.letsencrypt.org/directory"
	case "zerossl":
		return "https://acme.zerossl.com/v2/DV90"
	case "custom":
		return a.cfg.URL
	default:
		return "https://acme-v02.api.letsencrypt.org/directory"
	}
}

// RequestCertificate requests a certificate for the given domain via ACME
func (a *ACMEClient) RequestCertificate(domain string) error {
	a.mu.Lock()
	cfg := a.cfg
	dnsSet := a.dnsSetFunc
	dnsClear := a.dnsClearFunc
	a.mu.Unlock()

	if cfg.Email == "" {
		return fmt.Errorf("ACME email not configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Generate account key
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate account key: %w", err)
	}

	client := &acme.Client{
		Key:          accountKey,
		DirectoryURL: a.directoryURL(),
	}

	// Register account
	acct := &acme.Account{Contact: []string{"mailto:" + cfg.Email}}
	if _, err := client.Register(ctx, acct, acme.AcceptTOS); err != nil {
		// Already registered is OK
		slog.Info("ACME account registration", "component", "acme", "note", "may already exist", "error", err)
	}

	// Create order
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return fmt.Errorf("authorize order: %w", err)
	}

	// Process authorizations
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return fmt.Errorf("get authorization: %w", err)
		}

		if authz.Status == acme.StatusValid {
			continue
		}

		// Find challenge
		var challenge *acme.Challenge
		for _, ch := range authz.Challenges {
			if cfg.Challenge == "dns-01" && ch.Type == "dns-01" {
				challenge = ch
				break
			}
			if cfg.Challenge == "http-01" && ch.Type == "http-01" {
				challenge = ch
				break
			}
		}
		if challenge == nil {
			return fmt.Errorf("no %s challenge available", cfg.Challenge)
		}

		// Solve challenge
		if challenge.Type == "dns-01" {
			if dnsSet == nil {
				return fmt.Errorf("DNS solver not configured")
			}
			// Get the TXT record value
			txtValue, err := client.DNS01ChallengeRecord(challenge.Token)
			if err != nil {
				return fmt.Errorf("dns01 record: %w", err)
			}
			fqdn := "_acme-challenge." + domain
			if err := dnsSet(fqdn, txtValue); err != nil {
				return fmt.Errorf("set DNS TXT: %w", err)
			}
			defer func() {
				if dnsClear != nil {
					dnsClear(fqdn)
				}
			}()
			// Wait for DNS propagation — poll until TXT is visible or timeout
			slog.Info("waiting for DNS propagation", "component", "acme", "fqdn", fqdn)
			propagated := false
			for attempt := 0; attempt < 12; attempt++ {
				time.Sleep(10 * time.Second)
				// Check if TXT record is resolvable
				txts, err := net.LookupTXT(fqdn)
				if err == nil {
					for _, t := range txts {
						if t == txtValue {
							propagated = true
							break
						}
					}
				}
				if propagated {
					slog.Info("DNS propagation confirmed", "component", "acme", "fqdn", fqdn, "attempt", attempt+1)
					break
				}
				slog.Info("DNS not propagated yet, retrying", "component", "acme", "fqdn", fqdn, "attempt", attempt+1)
			}
			if !propagated {
				slog.Warn("DNS propagation timeout, proceeding anyway", "component", "acme", "fqdn", fqdn)
			}
		}

		// Accept challenge
		if _, err := client.Accept(ctx, challenge); err != nil {
			return fmt.Errorf("accept challenge: %w", err)
		}

		// Wait for authorization
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			return fmt.Errorf("wait authorization: %w", err)
		}
	}

	// Generate certificate key
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate cert key: %w", err)
	}

	// Create CSR
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}, certKey)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}

	// Finalize order
	derCerts, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("create cert: %w", err)
	}

	// Save certificate chain
	os.MkdirAll(a.certDir, 0755)
	certPath := filepath.Join(a.certDir, domain+".crt")
	keyPath := filepath.Join(a.certDir, domain+".key")

	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	for _, der := range derCerts {
		pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	certFile.Close()

	keyDER, _ := x509.MarshalECPrivateKey(certKey)
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	keyFile.Close()

	// Only copy as server.crt if no server cert exists yet
	// (block page certs should NOT overwrite the main server cert)
	serverCert := filepath.Join(a.certDir, "server.crt")
	serverKey := filepath.Join(a.certDir, "server.key")
	if _, err := os.Stat(serverCert); os.IsNotExist(err) {
		copyFile(certPath, serverCert)
		copyFile(keyPath, serverKey)
	}

	slog.Info("certificate obtained", "component", "acme", "domain", domain, "path", certPath)
	return nil
}

// GenerateSelfSignedForDomain creates a self-signed cert for a specific domain
func GenerateSelfSignedForDomain(domain, certDir string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: domain, Organization: []string{"DNS Supreme"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{domain, "*." + domain},
		IsCA:         true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}

	os.MkdirAll(certDir, 0755)
	certPath := filepath.Join(certDir, domain+".crt")
	keyPath := filepath.Join(certDir, domain+".key")

	certFile, _ := os.Create(certPath)
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certFile.Close()

	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyFile, _ := os.Create(keyPath)
	pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	keyFile.Close()

	slog.Info("self-signed certificate generated for domain", "component", "certs", "domain", domain)
	return nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

// --- Cloudflare DNS-01 solver ---

type cfZoneResult struct {
	Result []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"result"`
}

type cfRecordResult struct {
	Result []struct {
		ID string `json:"id"`
	} `json:"result"`
}

type cfCreateResult struct {
	Success bool `json:"success"`
}

func (a *ACMEClient) CloudflareDNSSet(fqdn, value string) error {
	token := a.cfg.CloudflareToken
	if token == "" {
		return fmt.Errorf("Cloudflare API token not configured")
	}

	// Find zone ID
	domain := extractDomain(fqdn)
	zoneID, err := cfGetZoneID(token, domain)
	if err != nil {
		return fmt.Errorf("failed to find Cloudflare zone for %s: %w", domain, err)
	}

	// Create TXT record
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", zoneID)
	body := fmt.Sprintf(`{"type":"TXT","name":"%s","content":"%s","ttl":120}`, fqdn, value)

	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Cloudflare API error: %s", string(respBody))
	}

	slog.Info("created TXT record", "component", "acme/cloudflare", "fqdn", fqdn)
	return nil
}

func (a *ACMEClient) CloudflareDNSClear(fqdn string) error {
	token := a.cfg.CloudflareToken
	if token == "" {
		return nil
	}

	domain := extractDomain(fqdn)
	zoneID, err := cfGetZoneID(token, domain)
	if err != nil {
		return nil // best effort
	}

	// Find TXT records matching fqdn
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?type=TXT&name=%s", zoneID, fqdn)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var result cfRecordResult
	json.NewDecoder(resp.Body).Decode(&result)

	for _, r := range result.Result {
		delURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneID, r.ID)
		delReq, _ := http.NewRequest("DELETE", delURL, nil)
		delReq.Header.Set("Authorization", "Bearer "+token)
		http.DefaultClient.Do(delReq)
	}

	slog.Info("cleared TXT records", "component", "acme/cloudflare", "fqdn", fqdn)
	return nil
}

func cfGetZoneID(token, domain string) (string, error) {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones?name=%s", domain)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result cfZoneResult
	json.NewDecoder(resp.Body).Decode(&result)
	if len(result.Result) == 0 {
		return "", fmt.Errorf("zone not found: %s", domain)
	}
	return result.Result[0].ID, nil
}

// extractDomain gets the root domain from an FQDN (e.g. _acme-challenge.example.com -> example.com)
func extractDomain(fqdn string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	parts := strings.Split(fqdn, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return fqdn
}

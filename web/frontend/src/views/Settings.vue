<template>
  <div class="settings-page">
    <h2>Settings</h2>

    <div class="tabs">
      <button v-for="t in settingsTabs" :key="t.id" :class="{ active: activeTab === t.id }" @click="activeTab = t.id" class="tab-btn">{{ t.label }}</button>
    </div>

    <!-- TAB: Server Identity -->
    <div v-if="activeTab === 'identity'" class="tab-content">
      <div class="identity-split">
        <div class="identity-left">
          <p class="section-desc">The hostname identifies this DNS Supreme instance (FQDN). It's used in SOA records and cluster communication.</p>
          <div class="settings-grid" style="margin-bottom: 12px">
            <div class="field">
              <label>Hostname (FQDN)</label>
              <input v-model="hostname" placeholder="ns1.example.com" />
            </div>
            <div class="field">
              <label>Primary Domain</label>
              <input v-model="primaryDomain" placeholder="example.com" />
            </div>
          </div>
          <p class="section-desc" style="font-size:0.75rem;margin-bottom:8px">Default: <code style="color:var(--accent)">dnssupreme.local</code>. When you change the primary domain, a zone is automatically created for it.</p>
          <button @click="saveIdentity" class="btn-primary">Save</button>
          <div v-if="hostnameMsg" class="msg-success">{{ hostnameMsg }}</div>
        </div>
        <div class="identity-right">
          <div class="hiw-panel">
            <h4>How Server Identity Works</h4>
            <div class="hiw-steps">
              <div class="hiw-step">
                <span class="hiw-num">1</span>
                <div><strong>Hostname (FQDN)</strong><br><span class="section-desc">The fully qualified domain name that identifies this DNS server. Used as the MNAME field in SOA records for all zones you host.</span></div>
              </div>
              <div class="hiw-step">
                <span class="hiw-num">2</span>
                <div><strong>Primary Domain</strong><br><span class="section-desc">The main domain this server is authoritative for. A DNS zone is automatically created when you set this. NS and SOA records point to your hostname.</span></div>
              </div>
              <div class="hiw-step">
                <span class="hiw-num">3</span>
                <div><strong>SOA Record</strong><br><span class="section-desc">Every zone gets a Start of Authority record with your hostname as the primary nameserver and admin@yourdomain as the contact.</span></div>
              </div>
            </div>
            <div class="hiw-tip">
              <strong>Tip:</strong> Use a real FQDN (e.g. <code>ns1.example.com</code>) if you plan to serve public DNS. For internal use, <code>ns1.dnssupreme.local</code> works fine.
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB: Clustering -->
    <div v-if="activeTab === 'cluster'" class="tab-content">
      <div class="identity-split">
        <div class="identity-left">
          <p class="section-desc">Connect two DNS Supreme instances as primary and secondary for high availability and zone replication.</p>

          <div class="mode-cards three-col">
            <div class="mode-card" :class="{ active: cluster.role === 'standalone' }" @click="setClusterRole('standalone')">
              <div class="mode-icon">1</div>
              <div class="mode-info">
                <span class="mode-title">Standalone</span>
                <span class="mode-desc">Single server, no replication</span>
              </div>
            </div>
            <div class="mode-card" :class="{ active: cluster.role === 'primary' }" @click="setClusterRole('primary')">
              <div class="mode-icon">P</div>
              <div class="mode-info">
                <span class="mode-title">Primary</span>
                <span class="mode-desc">Authoritative master, pushes zones to secondary</span>
              </div>
            </div>
            <div class="mode-card" :class="{ active: cluster.role === 'secondary' }" @click="setClusterRole('secondary')">
              <div class="mode-icon">S</div>
              <div class="mode-info">
                <span class="mode-title">Secondary</span>
                <span class="mode-desc">Replica, pulls zones from primary</span>
              </div>
            </div>
          </div>

          <div v-if="cluster.role !== 'standalone'" class="cluster-config">
            <!-- Peer Status -->
            <div class="cluster-status-panel" v-if="cluster.peer_address">
              <div class="cluster-status-header">
                <span class="cluster-status-dot" :class="clusterPeerStatus"></span>
                <span class="cluster-status-text">
                  Peer: <strong>{{ cluster.peer_address }}:{{ cluster.peer_port || 53 }}</strong>
                  — {{ clusterPeerStatus === 'online' ? 'Connected' : clusterPeerStatus === 'checking' ? 'Checking...' : 'Unreachable' }}
                </span>
                <span v-if="clusterLatency > 0" class="cluster-latency">{{ clusterLatency.toFixed(1) }}ms</span>
              </div>
              <button @click="testClusterPeer" :disabled="clusterPeerStatus === 'checking'" class="btn-test-peer">Test Connection</button>
              <span v-if="clusterError" class="cluster-error">{{ clusterError }}</span>
            </div>

            <div class="settings-grid">
              <div class="field">
                <label>Peer Address</label>
                <input v-model="cluster.peer_address" placeholder="192.168.1.2 or dns2.example.com" />
              </div>
              <div class="field">
                <label>Peer Port</label>
                <input v-model.number="cluster.peer_port" type="number" placeholder="53" />
              </div>
              <div class="field">
                <label>Shared Secret</label>
                <input v-model="cluster.shared_secret" type="password" placeholder="Used for TSIG authentication" />
              </div>
            </div>
            <div class="sync-options">
              <label class="checkbox-label"><input type="checkbox" v-model="cluster.sync_zones" /> Sync DNS zones</label>
              <label class="checkbox-label"><input type="checkbox" v-model="cluster.sync_blocklists" /> Sync blocklists</label>
              <label class="checkbox-label"><input type="checkbox" v-model="cluster.sync_settings" /> Sync settings</label>
            </div>
            <button @click="saveCluster" class="btn-primary" style="margin-top:12px">Save Cluster Settings</button>
            <div v-if="clusterMsg" class="msg-success">{{ clusterMsg }}</div>
          </div>
        </div>
        <div class="identity-right">
          <div class="hiw-panel">
            <h4>How Clustering Works</h4>
            <div class="hiw-steps">
              <div class="hiw-step">
                <span class="hiw-num">P</span>
                <div><strong>Primary Server</strong><br><span class="section-desc">The authoritative master. All zone changes are made here. It pushes zone updates to the secondary via AXFR (zone transfer) protocol.</span></div>
              </div>
              <div class="hiw-step">
                <span class="hiw-num">S</span>
                <div><strong>Secondary Server</strong><br><span class="section-desc">A read-only replica. It pulls zone data from the primary on a schedule and when notified of changes via DNS NOTIFY.</span></div>
              </div>
              <div class="hiw-step">
                <span class="hiw-num">HA</span>
                <div><strong>High Availability</strong><br><span class="section-desc">Both servers answer DNS queries independently. If the primary goes down, the secondary continues serving cached zones until it comes back.</span></div>
              </div>
            </div>
            <div class="hiw-tip">
              <strong>Tip:</strong> For best results, deploy primary and secondary on separate networks or data centers. Use the shared secret (TSIG) to authenticate zone transfers.
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB: DNS Services -->
    <div v-if="activeTab === 'dns'" class="tab-content">
      <div class="identity-split">
        <div class="identity-left">
          <p class="section-desc">Configure which protocols are enabled and network settings.</p>

          <div class="subsection">
            <h4>Protocols</h4>
            <div class="protocol-grid">
              <label class="protocol-item" v-for="p in protocols" :key="p.id">
                <input type="checkbox" v-model="p.enabled" @change="saveServerSettings" />
                <div class="protocol-info">
                  <span class="protocol-name">{{ p.name }}</span>
                  <span class="protocol-port">{{ p.port }}</span>
                  <span class="protocol-desc">{{ p.desc }}</span>
                </div>
              </label>
            </div>
          </div>

          <div class="subsection">
            <h4>Listener Addresses</h4>
            <p class="section-desc">Which addresses the DNS server will respond on.</p>
            <div class="settings-grid">
              <div class="field">
                <label>IPv4 Address</label>
                <input v-model="serverSettings.ipv4" placeholder="0.0.0.0 (all interfaces)" @change="saveServerSettings" />
              </div>
              <div class="field">
                <label>IPv6 Address</label>
                <input v-model="serverSettings.ipv6" placeholder=":: (all interfaces)" :disabled="!serverSettings.ipv6Enabled" @change="saveServerSettings" />
              </div>
              <div class="field">
                <label class="checkbox-label">
                  <input type="checkbox" v-model="serverSettings.ipv6Enabled" @change="saveServerSettings" />
                  Enable IPv6 support
                </label>
              </div>
            </div>
          </div>

          <div class="subsection">
            <h4>Cache & TTL</h4>
            <div class="settings-grid">
              <div class="field">
                <label>Cache Size (entries)</label>
                <input v-model.number="serverSettings.cacheSize" type="number" @change="saveServerSettings" />
              </div>
              <div class="field">
                <label>Default TTL (seconds)</label>
                <input v-model.number="serverSettings.defaultTTL" type="number" @change="saveServerSettings" />
              </div>
              <div class="field">
                <label>Minimum TTL (seconds)</label>
                <input v-model.number="serverSettings.minTTL" type="number" @change="saveServerSettings" />
              </div>
              <div class="field">
                <label>Maximum TTL (seconds)</label>
                <input v-model.number="serverSettings.maxTTL" type="number" @change="saveServerSettings" />
              </div>
            </div>
          </div>

          <div class="subsection">
            <h4>Management Panel HTTPS</h4>
            <p class="section-desc">Enable HTTPS for the management panel on port 53443.</p>
            <label class="checkbox-label">
              <input type="checkbox" v-model="serverSettings.mgmtHTTPS" />
              Enable HTTPS for management panel
            </label>
            <div v-if="mgmtHttpsChanged" class="mgmt-https-apply">
              <p class="section-desc" style="color:var(--warning);margin:8px 0">
                {{ serverSettings.mgmtHTTPS ? 'HTTPS will be enabled on port 53443.' : 'HTTPS for management panel will be disabled.' }}
                A server restart is required to apply this change.
              </p>
              <p v-if="serverSettings.mgmtHTTPS && !certInfo" class="section-desc" style="color:#f59e0b;margin:4px 0;font-size:0.78rem">
                No certificate configured. Go to the Certificates tab to generate or request one first.
              </p>
              <div style="display:flex;gap:8px">
                <button @click="applyMgmtHttps" class="btn-primary" :disabled="serverSettings.mgmtHTTPS && !certInfo">Apply &amp; Restart</button>
                <button @click="cancelMgmtHttps" class="btn-text">Cancel</button>
              </div>
            </div>
          </div>
          <div v-if="serverMsg" class="msg-success">{{ serverMsg }}</div>
        </div>
        <div class="identity-right">
          <div class="hiw-panel">
            <h4>Protocols</h4>
            <div class="hiw-steps">
              <div class="hiw-step">
                <span class="hiw-num">53</span>
                <div><strong>Standard DNS (UDP/TCP)</strong><br><span class="section-desc">The classic protocol. Unencrypted but universally supported. Every device on your network uses this by default.</span></div>
              </div>
              <div class="hiw-step">
                <span class="hiw-num">853</span>
                <div><strong>DNS-over-TLS (DoT)</strong><br><span class="section-desc">Encrypted DNS using TLS on a dedicated port. Supported by Android 9+ (Private DNS), systemd-resolved, and many DNS clients.</span></div>
              </div>
              <div class="hiw-step">
                <span class="hiw-num">443</span>
                <div><strong>DNS-over-HTTPS (DoH)</strong><br><span class="section-desc">DNS queries sent as HTTPS requests. Supported by all major browsers. Harder to block since it uses the same port as regular web traffic.</span></div>
              </div>
              <div class="hiw-step">
                <span class="hiw-num">853</span>
                <div><strong>DNS-over-QUIC (DoQ)</strong><br><span class="section-desc">The newest protocol, built on QUIC/UDP. Lower latency than DoT/DoH thanks to 0-RTT connection setup. Uses port 853/UDP.</span></div>
              </div>
            </div>
          </div>
          <div class="hiw-panel" style="margin-top:16px">
            <h4>Listener Addresses</h4>
            <div class="hiw-steps">
              <div class="hiw-step">
                <span class="hiw-num">v4</span>
                <div><strong>IPv4 Address</strong><br><span class="section-desc"><code>0.0.0.0</code> means the server listens on all network interfaces. Set a specific IP (e.g. <code>192.168.1.1</code>) to restrict which interface handles DNS queries.</span></div>
              </div>
              <div class="hiw-step">
                <span class="hiw-num">v6</span>
                <div><strong>IPv6 Address</strong><br><span class="section-desc"><code>::</code> listens on all IPv6 interfaces. Disable if your network doesn't use IPv6 to avoid binding errors.</span></div>
              </div>
            </div>
          </div>
          <div class="hiw-panel" style="margin-top:16px">
            <h4>Cache &amp; TTL</h4>
            <div class="hiw-steps">
              <div class="hiw-step">
                <span class="hiw-num">C</span>
                <div><strong>Cache Size</strong><br><span class="section-desc">Maximum number of DNS responses kept in memory. Larger cache = fewer upstream queries, but uses more RAM. 10,000 entries is good for most networks.</span></div>
              </div>
              <div class="hiw-step">
                <span class="hiw-num">T</span>
                <div><strong>TTL (Time to Live)</strong><br><span class="section-desc">How long a cached response is valid. <strong>Min TTL</strong> prevents very short upstream TTLs from overwhelming your forwarders. <strong>Max TTL</strong> forces cache refresh even if upstream says to keep it longer.</span></div>
              </div>
            </div>
          </div>
          <div class="hiw-panel" style="margin-top:16px">
            <h4>Management Panel</h4>
            <div class="hiw-steps">
              <div class="hiw-step">
                <span class="hiw-num">S</span>
                <div><strong>HTTPS for Web UI</strong><br><span class="section-desc">Encrypts the connection to this management panel (port 53443). Recommended if you access the panel over untrusted networks. Uses the same TLS certificate configured in the Certificates tab.</span></div>
              </div>
            </div>
            <div class="hiw-tip">
              <strong>Tip:</strong> After enabling HTTPS, access the panel at <code>https://your-server:53443</code>. The HTTP version on port 5380 stays available as fallback.
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB: DNS Forwarders -->
    <div v-if="activeTab === 'forwarders'" class="tab-content">
      <div class="fw-split">
        <div class="fw-left">
          <div class="forwarders-list">
            <div v-for="(fw, i) in forwarders" :key="i" class="forwarder-item">
              <div class="forwarder-num">{{ i + 1 }}</div>
              <div class="forwarder-info">
                <span class="forwarder-addr">{{ fw.address }}</span>
                <span class="forwarder-name">{{ fw.name }}</span>
              </div>
              <button @click="removeForwarder(i)" class="btn-icon-remove" title="Remove">&#x2715;</button>
            </div>
            <div v-if="!forwarders.length" class="empty-small">No forwarders configured</div>
          </div>

          <h4 class="fw-presets-title">Add from known providers</h4>
          <div class="fw-presets-rows">
            <div v-for="p in upstreamProviders" :key="p.name" class="fw-preset-row">
              <div class="fw-preset-row-info">
                <span class="fw-preset-name">{{ p.name }}</span>
                <span class="fw-preset-privacy">{{ p.privacy }}</span>
              </div>
              <div class="fw-preset-protocols">
                <button v-for="proto in p.protocols" :key="proto.addr"
                  @click="addForwarderDirect(proto.addr)"
                  :disabled="isForwarderAdded(proto.addr)"
                  :class="{ added: isForwarderAdded(proto.addr) }"
                  class="fw-proto-btn" :title="proto.addr">
                  <span class="fw-proto-badge" :class="proto.type">{{ proto.label }}</span>
                </button>
              </div>
            </div>
          </div>

          <div class="add-row" style="margin-top: 12px">
            <input v-model="newForwarder" placeholder="Manual: tls://..., https://..., or IP:port" @keyup.enter="addForwarder" class="url-input" />
            <button @click="addForwarder" :disabled="!newForwarder" class="btn-primary">Add</button>
          </div>
        </div>

        <div class="fw-right">
          <h4>How DNS Forwarding Works</h4>
          <div class="fw-explainer">
            <div class="fw-explain-step">
              <span class="fw-explain-num">1</span>
              <div><strong>Client query</strong><br><span class="section-desc">A device on your network asks DNS Supreme to resolve a domain.</span></div>
            </div>
            <div class="fw-explain-step">
              <span class="fw-explain-num">2</span>
              <div><strong>Local check</strong><br><span class="section-desc">DNS Supreme checks local zones, cache, and filtering rules first.</span></div>
            </div>
            <div class="fw-explain-step">
              <span class="fw-explain-num">3</span>
              <div><strong>Forward upstream</strong><br><span class="section-desc">If not resolved locally, the query is forwarded to the first available upstream server.</span></div>
            </div>
            <div class="fw-explain-step">
              <span class="fw-explain-num">4</span>
              <div><strong>Cache &amp; respond</strong><br><span class="section-desc">The response is cached and returned to the client.</span></div>
            </div>
          </div>
          <div class="fw-proto-legend">
            <h4 style="margin-top:16px">Protocols</h4>
            <div class="fw-legend-item"><span class="fw-proto-badge dns">DNS</span> Standard, unencrypted (port 53)</div>
            <div class="fw-legend-item"><span class="fw-proto-badge dot">DoT</span> DNS-over-TLS — encrypted (port 853)</div>
            <div class="fw-legend-item"><span class="fw-proto-badge doh">DoH</span> DNS-over-HTTPS — encrypted, firewall-friendly</div>
            <div class="fw-legend-item"><span class="fw-proto-badge doq">DoQ</span> DNS-over-QUIC — fastest encrypted protocol</div>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB: Certificates -->
    <div v-if="activeTab === 'certs'" class="tab-content">
      <div class="certs-split">
      <div class="certs-left">

      <!-- Certificate Mode Selector -->
      <div class="subsection">
        <h4>Server Certificate</h4>
        <div class="cert-mode-toggle">
          <button :class="{ active: certMode === 'self-signed' }" @click="certMode = 'self-signed'">Self-Signed</button>
          <button :class="{ active: certMode === 'acme' }" @click="certMode = 'acme'">ACME</button>
          <button :class="{ active: certMode === 'upload' }" @click="certMode = 'upload'">Upload Custom</button>
        </div>

        <!-- Active cert badge -->
        <div class="cert-active-badge" v-if="certInfo">
          <span class="cert-active-type">{{ certInfo.issuer?.includes('Let') ? 'ACME' : certInfo.subject === certInfo.issuer ? 'Self-Signed' : 'Custom' }}</span>
          in use
        </div>

      <!-- Current cert info (always visible) -->
      <div v-if="certInfo" class="cert-info">
        <div class="cert-status-bar" :class="certExpiryClass">
          <span class="cert-status-icon">{{ certExpired ? '!!' : certExpiryDays <= 30 ? '!' : 'OK' }}</span>
          <span>{{ certExpired ? 'EXPIRED' : certExpiryDays <= 30 ? 'Expiring soon (' + certExpiryDays + ' days)' : 'Valid (' + certExpiryDays + ' days remaining)' }}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Subject</span>
          <span class="detail-value">{{ certInfo.subject || 'Auto-generated self-signed' }}</span>
        </div>
        <div class="detail-row" v-if="certInfo.issuer">
          <span class="detail-label">Issuer</span>
          <span class="detail-value">{{ certInfo.issuer }}</span>
        </div>
        <div class="detail-row" v-if="certInfo.not_after">
          <span class="detail-label">Expires</span>
          <span class="detail-value">{{ formatDate(certInfo.not_after) }}</span>
        </div>
        <div class="detail-row" v-if="certInfo.dns_names?.length">
          <span class="detail-label">DNS Names</span>
          <span class="detail-value">{{ certInfo.dns_names.join(', ') }}</span>
        </div>
      </div>

      <!-- MODE: Self-Signed -->
      <div v-if="certMode === 'self-signed'" class="cert-mode-panel">
        <div class="settings-grid">
          <div class="field">
            <label>Common Name (hostname) *</label>
            <input v-model="certReq.common_name" :placeholder="hostname || 'dns-supreme'" />
          </div>
          <div class="field">
            <label>Organization</label>
            <input v-model="certReq.organization" placeholder="My Company" />
          </div>
          <div class="field">
            <label>Organizational Unit</label>
            <input v-model="certReq.organizational_unit" placeholder="IT Department" />
          </div>
          <div class="field">
            <label>Country (2-letter code)</label>
            <input v-model="certReq.country" placeholder="US" maxlength="2" style="text-transform:uppercase" />
          </div>
          <div class="field">
            <label>State / Province</label>
            <input v-model="certReq.state" placeholder="California" />
          </div>
          <div class="field">
            <label>City / Locality</label>
            <input v-model="certReq.locality" placeholder="San Francisco" />
          </div>
          <div class="field">
            <label>Additional DNS Names (comma-separated)</label>
            <input v-model="certDnsNamesStr" placeholder="dns.example.com, *.example.com" />
          </div>
          <div class="field">
            <label>Validity Period</label>
            <select v-model="certReq.validity_days">
              <option :value="365">1 year</option>
              <option :value="730">2 years</option>
              <option :value="1095">3 years</option>
              <option :value="1825">5 years</option>
              <option :value="3650">10 years</option>
            </select>
          </div>
        </div>
        <div class="section-actions" style="margin-top:12px">
          <button @click="generateCert" class="btn-primary">Generate Certificate</button>
          <button v-if="certInfo" @click="reissueCert" class="btn-secondary">Re-issue</button>
          <button v-if="certInfo" @click="deleteCert" class="btn-danger-outline">Delete</button>
        </div>
      </div>

      <!-- MODE: ACME / Let's Encrypt -->
      <div v-if="certMode === 'acme'" class="cert-mode-panel">
        <div class="settings-grid" style="margin-bottom:12px">
          <div class="field">
            <label>ACME Provider</label>
            <select v-model="acmeProvider">
              <option value="letsencrypt">Let's Encrypt</option>
              <option value="letsencrypt-staging">Let's Encrypt (Staging)</option>
              <option value="zerossl">ZeroSSL</option>
              <option value="custom">Custom ACME URL</option>
            </select>
          </div>
          <div class="field">
            <label>Email (required) *</label>
            <input v-model="acmeEmail" placeholder="admin@example.com" />
          </div>
          <div class="field" v-if="acmeProvider === 'custom'">
            <label>ACME Directory URL</label>
            <input v-model="acmeUrl" placeholder="https://acme.provider.com/directory" />
          </div>
          <div class="field">
            <label>Domain</label>
            <input v-model="acmeDomain" placeholder="dns.example.com" />
          </div>
          <div class="field">
            <label>Challenge Type</label>
            <select v-model="acmeChallenge">
              <option value="dns-01">DNS-01 (recommended)</option>
              <option value="http-01">HTTP-01 (requires port 80)</option>
            </select>
          </div>
          <div class="field" v-if="acmeChallenge === 'dns-01'">
            <label>DNS Provider</label>
            <select v-model="acmeDnsProvider">
              <option value="local">DNS Supreme (local zones)</option>
              <option value="cloudflare">Cloudflare</option>
            </select>
          </div>
          <div class="field" v-if="acmeDnsProvider === 'cloudflare'">
            <label>Cloudflare API Token</label>
            <input v-model="acmeCloudflareToken" type="password" placeholder="API token with Zone:DNS:Edit permission" />
          </div>
          <div class="field">
            <label>Auto-Renewal</label>
            <select v-model="acmeAutoRenew">
              <option :value="true">Enabled (renew 30 days before expiry)</option>
              <option :value="false">Disabled (manual renewal only)</option>
            </select>
          </div>
        </div>

        <div class="section-actions" style="margin-top:12px">
          <button @click="saveAcme" class="btn-primary">Save Settings</button>
          <button @click="requestAcmeCert" :disabled="!acmeEmail || !acmeDomain || acmeRequesting" class="btn-secondary">
            {{ acmeRequesting ? 'Requesting...' : 'Request Certificate' }}
          </button>
        </div>

        <!-- ACME Status -->
        <div class="acme-status" v-if="acmeStatus" style="margin-top:12px">
          <div class="detail-row">
            <span class="detail-label">Status</span>
            <span class="detail-value">
              <span class="acme-status-badge" :class="acmeStatus.status">
                {{ acmeStatus.status === 'pending' ? 'Requesting...' : acmeStatus.status === 'issued' ? 'Issued' : acmeStatus.status === 'failed' ? 'Failed' : acmeStatus.status }}
              </span>
            </span>
          </div>
          <div class="detail-row" v-if="acmeStatus.domain">
            <span class="detail-label">Domain</span>
            <span class="detail-value">{{ acmeStatus.domain }}</span>
          </div>
          <div class="detail-row" v-if="acmeStatus.error">
            <span class="detail-label">Error</span>
            <span class="detail-value" style="color:#ef4444;font-size:0.78rem">{{ acmeStatus.error }}</span>
          </div>
          <div v-if="acmeStatus.status === 'issued'" class="acme-apply">
            <p class="section-desc" style="color:#22c55e;margin:8px 0">Certificate issued successfully. Restart to apply.</p>
            <button @click="applyAcmeCert" class="btn-primary">Apply &amp; Restart</button>
          </div>
          <div v-if="acmeStatus.status === 'failed'" style="margin-top:8px">
            <button @click="requestAcmeCert" :disabled="acmeRequesting" class="btn-secondary">Retry</button>
          </div>
        </div>

        <div v-if="acmeMsg" :class="acmeMsg.startsWith('Failed') ? 'msg-error' : 'msg-success'" style="margin-top:8px">{{ acmeMsg }}</div>
      </div>

      <!-- MODE: Upload Custom -->
      <div v-if="certMode === 'upload'" class="cert-mode-panel">
        <p class="section-desc">Upload a certificate and private key from an external CA.</p>
        <div class="section-actions">
          <label class="btn-primary upload-btn">
            Select Certificate File (.pem / .crt)
            <input type="file" ref="certFileInput" @change="handleCertUpload" style="display:none" accept=".pem,.crt" />
          </label>
          <button v-if="certInfo" @click="deleteCert" class="btn-danger-outline">Delete</button>
        </div>
      </div>

      <div v-if="certMsg" class="msg-success" style="margin-top:8px">{{ certMsg }}</div>

      <!-- Cert key upload modal -->
      <div v-if="certUploadShow" class="modal-overlay" @click.self="certUploadShow = false">
        <div class="edit-modal">
          <h3>Upload Private Key</h3>
          <p class="section-desc">Paste the PEM-encoded private key content for the certificate you just selected.</p>
          <div class="field">
            <label>Private Key (PEM)</label>
            <textarea v-model="certUploadKeyText" class="code-editor" rows="8" placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"></textarea>
          </div>
          <div class="section-actions" style="margin-top:12px">
            <button @click="submitCertUpload" :disabled="!certUploadKeyText" class="btn-primary">Upload</button>
            <button @click="certUploadShow = false" class="btn-secondary">Cancel</button>
          </div>
        </div>
      </div>

      <!-- Delete confirmation modal (type DELETE) -->
      <div v-if="certDeleteShow" class="modal-overlay" @click.self="certDeleteShow = false">
        <div class="edit-modal">
          <h3>Confirm Certificate Deletion</h3>
          <p class="section-desc">This action is irreversible. Type <strong>DELETE</strong> below to confirm.</p>
          <div class="field">
            <input v-model="certDeleteConfirmText" placeholder="Type DELETE to confirm" autocomplete="off" />
          </div>
          <div class="section-actions" style="margin-top:12px">
            <button @click="confirmDeleteCert" :disabled="certDeleteConfirmText !== 'DELETE'" class="btn-danger">Delete Certificate</button>
            <button @click="certDeleteShow = false" class="btn-secondary">Cancel</button>
          </div>
        </div>
      </div>

      <!-- Export -->
      <div class="cert-export" v-if="certInfo">
        <h4 style="margin-top:16px">Export Certificate</h4>
        <p class="section-desc">Download the CA certificate to distribute to clients. Install it as a trusted root CA so browsers and devices trust your self-signed HTTPS connections.</p>
        <div class="section-actions">
          <button @click="exportCert('pem')" class="btn-secondary">Download CA Certificate (.pem)</button>
          <button @click="exportCert('der')" class="btn-secondary">Download CA Certificate (.crt / DER)</button>
        </div>
        <div class="cert-install-hints">
          <details>
            <summary>How to install on clients</summary>
            <div class="cert-hint-content">
              <p><strong>Windows:</strong> Double-click the .crt file, select "Install Certificate", choose "Local Machine" > "Trusted Root Certification Authorities".</p>
              <p><strong>macOS:</strong> Double-click the .pem file, add to Keychain, then in Keychain Access set it to "Always Trust".</p>
              <p><strong>Linux:</strong> Copy .pem to <code>/usr/local/share/ca-certificates/</code> and run <code>update-ca-certificates</code>.</p>
              <p><strong>iOS:</strong> Email or host the .pem file, open on device, install profile in Settings > General > Profiles, then enable in Settings > General > About > Certificate Trust Settings.</p>
              <p><strong>Android:</strong> Settings > Security > Install from storage, select the .pem file.</p>
              <p><strong>Group Policy (Windows domain):</strong> Distribute via GPO under Computer Configuration > Policies > Windows Settings > Security Settings > Public Key Policies > Trusted Root CAs.</p>
            </div>
          </details>
        </div>
      </div>
      </div>

      <!-- Per-zone certificates -->
      <div class="subsection" style="margin-top:20px">
        <h4>Zone Certificates</h4>
        <p class="section-desc">Generate or upload TLS certificates per domain. Useful for DoH and HTTPS block pages with proper domain names.</p>
        <div v-if="certZones.length" class="cert-zones-list">
          <div v-for="z in certZones" :key="z.name" class="cert-zone-row">
            <div class="cert-zone-info">
              <span class="cert-zone-name">{{ z.name }}</span>
              <span v-if="z.has_cert" class="cert-zone-status has">Certificate installed</span>
              <span v-else class="cert-zone-status none">No certificate</span>
            </div>
            <div class="cert-zone-actions">
              <button @click="generateZoneCert(z.name)" class="btn-sm">Generate</button>
              <button v-if="z.has_cert" @click="exportCert('pem', z.name)" class="btn-sm">Export</button>
            </div>
          </div>
        </div>
        <div v-else class="empty-small">No zones configured. Create zones first in DNS Zones.</div>
      </div>

      </div><!-- end certs-left -->

      <div class="certs-right">
        <div class="how-it-works">
          <h4>How It Works</h4>

          <div class="hiw-section" v-if="certMode === 'self-signed'">
            <h5>Self-Signed Certificate</h5>
            <p>Creates a certificate signed by your own server. Encrypts all traffic but browsers will show a "not trusted" warning.</p>
            <p><strong>When to use:</strong></p>
            <ul>
              <li>Internal or private network DNS</li>
              <li>Development and testing</li>
              <li>DNS-over-TLS — clients can pin the cert</li>
            </ul>
            <p><strong>How to set up:</strong></p>
            <ol>
              <li>Fill in your server hostname as Common Name</li>
              <li>Add organization details (optional but recommended)</li>
              <li>Add any extra DNS names the server responds to</li>
              <li>Choose validity period</li>
              <li>Click "Generate Certificate"</li>
              <li>Click "Apply Now" in the banner to reload TLS</li>
            </ol>
            <p><strong>To trust on clients:</strong> Export the certificate below and install it as a trusted root CA on each device (see install hints).</p>
          </div>

          <div class="hiw-section" v-if="certMode === 'acme'">
            <h5>Let's Encrypt / ACME</h5>
            <p>Obtains a <strong>free, trusted certificate</strong> from Let's Encrypt that all browsers and devices accept automatically. No manual install needed on clients.</p>
            <p><strong>Requirements:</strong></p>
            <ul>
              <li>A real domain name (not .local)</li>
              <li>Domain's DNS must point to this server's IP</li>
              <li>A DNS zone for the domain in DNS Zones</li>
            </ul>
            <p><strong>How to set up:</strong></p>
            <ol>
              <li>Enter your email address (Let's Encrypt requires it)</li>
              <li>Enter the domain name for the certificate</li>
              <li>Select <strong>DNS-01</strong> challenge (recommended)</li>
              <li>Click "Save Settings"</li>
              <li>Click "Request Certificate Now"</li>
              <li>DNS Supreme auto-creates the TXT record needed</li>
              <li>Certificate is issued in seconds</li>
            </ol>
            <p><strong>DNS-01 vs HTTP-01:</strong></p>
            <ul>
              <li><strong>DNS-01</strong> — Recommended. DNS Supreme creates _acme-challenge TXT record automatically. Works even behind firewall. Supports wildcards.</li>
              <li><strong>HTTP-01</strong> — Requires port 80 accessible from internet. No wildcard support.</li>
            </ul>
            <p><strong>Auto-renewal:</strong> When enabled, the certificate renews automatically 30 days before expiry.</p>
            <p><strong>Note:</strong> Let's Encrypt issues certificates per domain — each domain needs its own request. Wildcard certs (*.example.com) are included automatically with DNS-01.</p>
          </div>

          <div class="hiw-section" v-if="certMode === 'upload'">
            <h5>Upload Custom Certificate</h5>
            <p>Upload a certificate from any Certificate Authority (DigiCert, Comodo, GoDaddy, etc.)</p>
            <p><strong>How to set up:</strong></p>
            <ol>
              <li>Click "Select Certificate File"</li>
              <li>Choose your .pem or .crt file</li>
              <li>Paste the private key (PEM format)</li>
              <li>Click Upload, then "Apply Now"</li>
            </ol>
            <p><strong>Supported formats:</strong> PEM-encoded certificate (.pem, .crt) and PEM-encoded private key.</p>
          </div>

          <div class="hiw-section">
            <h5>What the certificate protects</h5>
            <ul>
              <li><strong>DoT</strong> (port 853) — DNS-over-TLS encryption</li>
              <li><strong>DoH</strong> (port 443) — DNS-over-HTTPS encryption</li>
              <li><strong>DoQ</strong> (port 853/UDP) — DNS-over-QUIC encryption</li>
              <li><strong>Block Page</strong> (port 443) — HTTPS block page</li>
              <li><strong>Web Panel</strong> — if HTTPS is enabled for management</li>
            </ul>
          </div>

          <div class="hiw-section">
            <h5>Zone Certificates</h5>
            <p>Each DNS zone can have its own certificate. Useful when:</p>
            <ul>
              <li>You host multiple domains</li>
              <li>Different domains need different certs</li>
              <li>DoH clients connect to specific domain names</li>
            </ul>
            <p>Generate a zone cert below — it creates a self-signed cert with the zone domain and wildcard (*.domain) as SANs.</p>
          </div>
        </div>
      </div><!-- end certs-right -->
      </div><!-- end certs-split -->
    </div>

    <!-- TAB: Block Page -->
    <div v-if="activeTab === 'blockpage'" class="tab-content">
      <!-- Block Page Domain — split layout -->
      <div class="bp-domain-split">
        <div class="bp-domain-left">
          <h4>Block Page Domain</h4>
          <p class="section-desc">Configure a domain for your block page. Blocked sites will redirect here, with a valid TLS certificate.</p>
          <div class="bp-domain-row">
            <div class="field" style="flex:0 0 160px">
              <label>Subdomain</label>
              <input v-model="bpPrefix" placeholder="denied" />
            </div>
            <span class="bp-domain-dot">.</span>
            <div class="field" style="flex:1">
              <label>Zone</label>
              <select v-model="bpZone">
                <option value="" disabled>Select a zone...</option>
                <option v-for="z in bpZones" :key="z" :value="z">{{ z }}</option>
              </select>
            </div>
          </div>
          <div class="bp-domain-preview" v-if="bpPrefix && bpZone">
            <span class="bp-preview-label">Block page URL:</span>
            <code class="bp-preview-domain">{{ bpPrefix }}.{{ bpZone }}</code>
          </div>
          <div style="display:flex;gap:8px;align-items:center;margin-top:10px">
            <button @click="setupBpDomain" :disabled="!bpPrefix || !bpZone || bpSetupLoading" class="btn-primary">
              {{ bpSetupLoading ? 'Setting up...' : 'Setup Block Page' }}
            </button>
            <button v-if="bpDomain" @click="clearBpDomain" class="btn-secondary">Clear</button>
          </div>
          <p v-if="bpDomainMsg" :class="bpDomainMsg.startsWith('Failed') ? 'msg-error' : 'msg-success'" style="margin-top:8px">{{ bpDomainMsg }}</p>
        </div>
        <div class="bp-domain-right">
          <h4>Status</h4>
          <div v-if="bpDomain" class="bp-domain-status">
            <div class="bp-status-row">
              <span class="bp-status-label">Domain</span>
              <code>{{ bpDomain }}</code>
            </div>
            <div class="bp-status-row">
              <span class="bp-status-label">Redirect</span>
              <code>{{ bpRedirectURL || 'Not set' }}</code>
            </div>
            <div class="bp-status-row">
              <span class="bp-status-label">Certificate</span>
              <span :class="bpCertStatus === 'issued' ? 'bp-cert-ok' : bpCertStatus === 'requesting' ? 'bp-cert-pending' : 'bp-cert-none'">
                {{ bpCertStatus === 'issued' ? 'Valid' : bpCertStatus === 'requesting' ? 'Requesting...' : bpCertStatus === 'failed' ? 'Failed' : 'None' }}
              </span>
              <button v-if="bpCertStatus === 'failed' || bpCertStatus === 'none'" @click="setupBpDomain" class="btn-sm">Retry</button>
            </div>
          </div>
          <div v-else class="bp-status-empty">No block page domain configured</div>
        </div>
      </div>

      <div class="bp-split">
        <!-- Left: Builder -->
        <div class="bp-builder">
          <div class="bp-mode-switch">
            <button :class="{ active: bpMode === 'visual' }" @click="bpMode = 'visual'" class="bp-mode-btn">Visual Builder</button>
            <button :class="{ active: bpMode === 'html' }" @click="bpMode = 'html'" class="bp-mode-btn">Custom HTML</button>
          </div>

          <div v-if="bpMode === 'visual'" class="bp-visual">
            <div class="field">
              <label>Logo</label>
              <div style="display:flex;gap:8px;align-items:start;flex-direction:column">
                <div style="display:flex;gap:8px;width:100%;align-items:center">
                  <input v-model="bpLogo" placeholder="https://example.com/logo.png or leave empty" @input="updateBpFromVisual" style="flex:1" />
                  <label class="btn-upload">
                    Upload
                    <input type="file" accept="image/*" @change="uploadLogo" style="display:none" />
                  </label>
                </div>
                <div v-if="bpLogo" style="display:flex;align-items:center;gap:8px">
                  <img :src="bpLogo" style="max-height:32px;max-width:120px;border-radius:4px;border:1px solid var(--border)" />
                  <button @click="bpLogo = ''; updateBpFromVisual()" class="btn-text" style="font-size:0.75rem;color:var(--danger)">Remove</button>
                </div>
                <span v-if="logoUploading" style="color:var(--text-muted);font-size:0.8rem">Uploading...</span>
              </div>
            </div>
            <div class="field">
              <label>Heading</label>
              <input v-model="bpHeading" placeholder="Access Blocked" @input="updateBpFromVisual" />
            </div>
            <div class="field">
              <label>Message</label>
              <textarea v-model="bpMessage" rows="3" placeholder="Access to this page has been blocked by your network administrator." @input="updateBpFromVisual"></textarea>
            </div>
            <div class="field">
              <label>Optional Message</label>
              <textarea v-model="bpDescription" rows="2" placeholder="Additional message shown below the main message" @input="updateBpFromVisual"></textarea>
            </div>
            <div class="field">
              <label>Footer (optional)</label>
              <input v-model="bpFooter" placeholder="Protected by DNS Supreme" @input="updateBpFromVisual" />
            </div>
            <div class="field">
              <label>Accent Color</label>
              <div style="display:flex;gap:6px;align-items:center">
                <input type="color" v-model="bpColor" @input="updateBpFromVisual" style="width:36px;height:30px;border:none;cursor:pointer" />
                <span style="color:var(--text-muted);font-size:0.8rem">{{ bpColor }}</span>
              </div>
            </div>
            <p class="section-desc" style="font-size:0.75rem">Variables: <code v-pre>{{.Domain}}</code> = blocked domain, <code v-pre>{{.Reason}}</code> = block reason</p>
          </div>

          <div v-if="bpMode === 'html'" class="bp-html-mode">
            <p class="section-desc">Paste full HTML. Use <code v-pre>{{.Domain}}</code> and <code v-pre>{{.Reason}}</code> as variables.</p>
            <textarea v-model="blockPageHTML" class="code-editor" rows="18" placeholder="Paste custom HTML here..."></textarea>
          </div>

          <div class="section-actions" style="margin-top:12px">
            <button @click="saveBlockPage" class="btn-primary">Save</button>
            <button @click="resetBlockPage" class="btn-text">Reset to Default</button>
          </div>
          <div v-if="bpMsg" class="msg-success">{{ bpMsg }}</div>
        </div>

        <!-- Right: Live Preview -->
        <div class="bp-preview-wrap">
          <h4>Preview</h4>
          <div class="bp-preview-frame">
            <iframe :srcdoc="bpPreviewHTML" class="bp-iframe"></iframe>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB: Log Management -->
    <div v-if="activeTab === 'logs'" class="tab-content">
      <p class="section-desc">Configure how long query logs are kept, and manage log data.</p>

      <div class="settings-grid" style="margin-bottom:16px">
        <div class="field">
          <label>Retention Period (days)</label>
          <input v-model.number="logRetention.days" type="number" min="1" />
        </div>
        <div class="field">
          <label class="checkbox-label">
            <input type="checkbox" v-model="logRetention.autoCleanup" />
            Auto-delete logs older than retention period
          </label>
        </div>
      </div>
      <button @click="saveLogRetention" class="btn-primary" style="margin-bottom:16px">Save Retention Settings</button>

      <div v-if="logStats" class="log-stats-grid">
        <div class="info-item"><span class="info-label">Total Entries</span><span class="info-value">{{ logStats.total_entries?.toLocaleString() }}</span></div>
        <div class="info-item"><span class="info-label">Oldest Entry</span><span class="info-value">{{ logStats.oldest_entry ? formatDate(logStats.oldest_entry) : 'None' }}</span></div>
        <div class="info-item"><span class="info-label">Newest Entry</span><span class="info-value">{{ logStats.newest_entry ? formatDate(logStats.newest_entry) : 'None' }}</span></div>
        <div class="info-item"><span class="info-label">Est. Size</span><span class="info-value">{{ logStats.size_estimate }}</span></div>
      </div>

      <div class="section-actions" style="margin-top:12px">
        <button @click="exportLogs(7)" class="btn-secondary">Export Last 7 Days (CSV)</button>
        <button @click="exportLogs(30)" class="btn-secondary">Export Last 30 Days</button>
        <button @click="deleteOldLogs" class="btn-danger">Delete Logs Older Than...</button>
        <button @click="deleteAllLogs" class="btn-danger-outline">Delete All Logs</button>
      </div>
      <div v-if="logMsg" class="msg-success">{{ logMsg }}</div>
    </div>

    <!-- TAB: Mail -->
    <div v-if="activeTab === 'mail'" class="tab-content">
      <p class="section-desc">Configure SMTP server for sending email notifications (alerts, reports, password resets).</p>

      <div class="settings-grid">
        <div class="field">
          <label>SMTP Server</label>
          <input v-model="mailSettings.host" placeholder="smtp.example.com" />
        </div>
        <div class="field">
          <label>Port</label>
          <input v-model.number="mailSettings.port" type="number" placeholder="587" />
        </div>
        <div class="field">
          <label>Username</label>
          <input v-model="mailSettings.username" placeholder="user@example.com" />
        </div>
        <div class="field">
          <label>Password</label>
          <input v-model="mailSettings.password" type="password" placeholder="App password or SMTP password" />
        </div>
        <div class="field">
          <label>From Address</label>
          <input v-model="mailSettings.from" placeholder="dns-supreme@example.com" />
        </div>
        <div class="field">
          <label>From Name</label>
          <input v-model="mailSettings.fromName" placeholder="DNS Supreme" />
        </div>
        <div class="field">
          <label>Encryption</label>
          <select v-model="mailSettings.encryption">
            <option value="starttls">STARTTLS (port 587)</option>
            <option value="ssl">SSL/TLS (port 465)</option>
            <option value="none">None (port 25)</option>
          </select>
        </div>
        <div class="field" style="grid-column: 1/-1">
          <label>Notification Recipients</label>
          <p class="section-desc" style="margin-bottom:6px">Comma-separated email addresses to receive notifications. Leave empty to use admin user emails.</p>
          <input v-model="mailSettings.recipients" placeholder="admin@example.com, ops@example.com" />
        </div>
      </div>

      <div class="section-actions" style="margin-top:16px">
        <button @click="saveMailSettings" class="btn-primary">Save</button>
        <button @click="testMail" :disabled="!mailSettings.host || !mailSettings.from" class="btn-secondary">Send Test Email</button>
      </div>
      <div v-if="mailMsg" class="msg-success">{{ mailMsg }}</div>

      <div class="subsection" style="margin-top:24px">
        <h4>Email Notifications</h4>
        <p class="section-desc">Choose which events trigger email notifications.</p>
        <div class="mail-notif-list">
          <h5 style="color:var(--text-muted);margin-bottom:8px;font-weight:500">Security</h5>
          <label class="checkbox-label"><input type="checkbox" v-model="mailNotifs.securityAlerts" /> Failed login attempts &amp; IP bans</label>
          <label class="checkbox-label"><input type="checkbox" v-model="mailNotifs.userChanges" /> User created, deleted, or role changed</label>
          <label class="checkbox-label"><input type="checkbox" v-model="mailNotifs.configChanges" /> Settings or policy changes</label>

          <h5 style="color:var(--text-muted);margin:12px 0 8px;font-weight:500">Certificates</h5>
          <label class="checkbox-label"><input type="checkbox" v-model="mailNotifs.certExpiry" /> Certificate expiring within 30 days</label>
          <label class="checkbox-label"><input type="checkbox" v-model="mailNotifs.certRenewal" /> Certificate renewed or replaced</label>

          <h5 style="color:var(--text-muted);margin:12px 0 8px;font-weight:500">System Health</h5>
          <label class="checkbox-label"><input type="checkbox" v-model="mailNotifs.feedErrors" /> Blocklist or threat feed update failures</label>
          <label class="checkbox-label"><input type="checkbox" v-model="mailNotifs.highBlockRate" /> Abnormal block rate (&gt;90%)</label>
          <label class="checkbox-label"><input type="checkbox" v-model="mailNotifs.diskUsage" /> Disk usage above 85%</label>
          <label class="checkbox-label"><input type="checkbox" v-model="mailNotifs.dnsErrors" /> DNS upstream forwarder failures</label>

          <h5 style="color:var(--text-muted);margin:12px 0 8px;font-weight:500">Cluster</h5>
          <label class="checkbox-label"><input type="checkbox" v-model="mailNotifs.clusterOffline" /> Cluster peer went offline</label>
          <label class="checkbox-label"><input type="checkbox" v-model="mailNotifs.axfrRequests" /> Zone transfer (AXFR) requests</label>

          <h5 style="color:var(--text-muted);margin:12px 0 8px;font-weight:500">Reports</h5>
          <label class="checkbox-label"><input type="checkbox" v-model="mailNotifs.dailyReport" /> Daily summary report</label>
          <label class="checkbox-label"><input type="checkbox" v-model="mailNotifs.weeklyReport" /> Weekly summary report</label>
        </div>
        <button @click="saveMailSettings" class="btn-primary" style="margin-top:12px">Save Notifications</button>
      </div>
    </div>

    <!-- TAB: Users & Security -->
    <div v-if="activeTab === 'users'" class="tab-content">
      <div class="users-split">
        <!-- Left: Users -->
        <div class="users-left">
          <h4>Create User</h4>
          <form class="user-form" @submit.prevent="createUser">
            <input v-model="userForm.username" placeholder="Username" required />
            <input v-model="userForm.password" type="password" placeholder="Password" required />
            <input v-model="userForm.first_name" placeholder="First Name" />
            <input v-model="userForm.last_name" placeholder="Last Name" />
            <input v-model="userForm.email" type="email" placeholder="Email" />
            <select v-model="userForm.role">
              <option value="viewer">Viewer</option>
              <option value="admin">Admin</option>
            </select>
            <button type="submit" class="btn-primary">Create</button>
          </form>
          <div v-if="userFormError" class="error-msg" style="margin-top:8px">{{ userFormError }}</div>
          <div v-if="userFormSuccess" class="msg-success">{{ userFormSuccess }}</div>

          <h4 style="margin-top:20px">Users</h4>
          <table>
            <thead>
              <tr><th>Username</th><th>Name</th><th>Role</th><th>MFA</th><th>Actions</th></tr>
            </thead>
            <tbody>
              <tr v-for="u in users" :key="u.id">
                <td class="username">{{ u.username }}</td>
                <td>{{ u.first_name }} {{ u.last_name }}</td>
                <td><span class="user-badge" :class="u.role">{{ u.role }}</span></td>
                <td>
                  <span v-if="u.mfa_enabled" class="mfa-on">TOTP</span>
                  <button v-else @click="setupUserMFA(u)" class="btn-sm">Enable</button>
                </td>
                <td class="actions">
                  <button @click="editUser(u)" class="btn-sm">Edit</button>
                  <button @click="openResetPw(u)" class="btn-sm warn">Reset PW</button>
                  <button v-if="u.mfa_enabled" @click="disableUserMFA(u)" class="btn-sm">Disable MFA</button>
                  <button @click="deleteUser(u)" class="btn-sm danger" v-if="u.username !== currentUsername">Delete</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Right: Security -->
        <div class="users-right">
          <!-- Fail2Ban -->
          <div class="security-card">
            <div class="security-card-header">
              <h4>Fail2Ban</h4>
              <div class="toggle" :class="{ on: f2bSettings.enabled }" @click="toggleFail2Ban"><div class="toggle-knob"></div></div>
            </div>
            <p class="section-desc">Automatically block IPs after repeated failed login attempts.</p>
            <div class="settings-grid" style="margin-bottom:12px">
              <div class="field">
                <label>Max retries</label>
                <input v-model.number="f2bSettings.max_retries" type="number" min="1" @change="saveFail2Ban" />
              </div>
              <div class="field">
                <label>Ban duration (minutes)</label>
                <input v-model.number="f2bBanMinutes" type="number" min="1" @change="saveFail2Ban" />
              </div>
            </div>

            <div v-if="f2bBanned.length" class="f2b-banned">
              <h4>Blocked IPs <span class="f2b-count">{{ f2bBanned.length }}</span></h4>
              <div v-for="b in f2bBanned" :key="b.ip" class="f2b-row">
                <div class="f2b-row-info">
                  <span class="f2b-ip">{{ b.ip }}</span>
                  <span class="f2b-detail">{{ b.attempts }} attempts &middot; expires {{ formatRelative(b.expires_at) }}</span>
                </div>
                <button @click="unbanIP(b.ip)" class="btn-sm">Unban</button>
              </div>
            </div>
            <div v-else class="empty-small">No blocked IPs</div>
          </div>

          <!-- Access Control -->
          <div class="security-card" style="margin-top:16px">
            <h4>Access Control</h4>
            <p class="section-desc">Restrict management panel access to specific IP addresses. Leave empty to allow all.</p>
            <div class="add-row" style="margin-bottom:8px">
              <input v-model="newAllowedIP" placeholder="IP address (e.g. 192.168.1.0/24)" @keyup.enter="addAllowedIP" />
              <button @click="addAllowedIP" :disabled="!newAllowedIP" class="btn-primary">Add</button>
            </div>
            <div class="f2b-banned" v-if="allowedIPs.length">
              <div v-for="ip in allowedIPs" :key="ip" class="f2b-row">
                <span class="f2b-ip">{{ ip }}</span>
                <button @click="removeAllowedIP(ip)" class="btn-sm danger">Remove</button>
              </div>
            </div>
            <div v-else class="empty-small">No restrictions — all IPs can access the panel</div>
          </div>

          <!-- MFA Method -->
          <div class="security-card" style="margin-top:16px">
            <h4>MFA Methods</h4>
            <p class="section-desc">Available multi-factor authentication methods for users.</p>
            <label class="checkbox-label"><input type="checkbox" checked disabled /> TOTP (Authenticator app)</label>
            <label class="checkbox-label"><input type="checkbox" v-model="mfaEmailEnabled" /> Email code (requires SMTP configured in Mail tab)</label>
          </div>
        </div>
      </div>

      <!-- Modals (same as before) -->
      <div v-if="resetPwUser" class="modal-overlay" @click.self="resetPwUser = null">
        <div class="edit-modal">
          <h3>Reset Password: {{ resetPwUser.username }}</h3>
          <div class="field"><label>New Password</label><input v-model="resetPwValue" type="password" placeholder="Enter new password" /></div>
          <div class="field"><label>Confirm Password</label><input v-model="resetPwConfirm" type="password" placeholder="Confirm password" /></div>
          <div v-if="resetPwError" class="error-msg" style="margin-top:8px">{{ resetPwError }}</div>
          <div class="section-actions" style="margin-top:16px">
            <button @click="submitResetPw" :disabled="!resetPwValue || resetPwValue !== resetPwConfirm" class="btn-primary">Reset Password</button>
            <button @click="resetPwUser = null" class="btn-secondary">Cancel</button>
          </div>
        </div>
      </div>

      <div v-if="mfaSetupUser" class="modal-overlay" @click.self="mfaSetupUser = null">
        <div class="edit-modal">
          <h3>Setup TOTP: {{ mfaSetupUser.username }}</h3>
          <div v-if="mfaSetup">
            <p class="section-desc">Scan with authenticator app or enter secret manually:</p>
            <canvas ref="qrCanvas" style="margin:12px auto;display:block;border-radius:8px"></canvas>
            <div class="mfa-secret">{{ mfaSetup.secret }}</div>
            <form @submit.prevent="enableMFA" class="mfa-verify">
              <input v-model="mfaVerifyCode" placeholder="6-digit code" maxlength="6" />
              <button type="submit" class="btn-primary">Enable</button>
            </form>
            <div v-if="mfaError" class="error-msg" style="margin-top:8px">{{ mfaError }}</div>
          </div>
        </div>
      </div>

      <!-- Recovery Codes Modal -->
      <div v-if="recoveryCodes.length" class="modal-overlay" @click.self="recoveryCodes = []">
        <div class="edit-modal" style="max-width:420px">
          <h3>Recovery Codes</h3>
          <p class="section-desc" style="margin-bottom:12px">Save these codes in a safe place. Each code can only be used once to sign in if you lose access to your authenticator app.</p>
          <div class="recovery-codes-grid">
            <code v-for="c in recoveryCodes" :key="c" class="recovery-code">{{ c }}</code>
          </div>
          <button @click="copyRecoveryCodes" class="btn-primary" style="margin-top:16px;width:100%">Copy All Codes</button>
          <button @click="recoveryCodes = []" class="btn-text" style="margin-top:8px;width:100%">I've saved my codes</button>
        </div>
      </div>

      <div v-if="editingUser" class="modal-overlay" @click.self="editingUser = null">
        <div class="edit-modal">
          <h3>Edit: {{ editingUser.username }}</h3>
          <form @submit.prevent="saveUserEdit">
            <div class="field"><label>First Name</label><input v-model="editingUser.first_name" /></div>
            <div class="field"><label>Last Name</label><input v-model="editingUser.last_name" /></div>
            <div class="field"><label>Email</label><input v-model="editingUser.email" type="email" /></div>
            <div class="field"><label>Role</label>
              <select v-model="editingUser.role"><option value="viewer">Viewer</option><option value="admin">Admin</option></select>
            </div>
            <div class="section-actions" style="margin-top:16px">
              <button type="submit" class="btn-primary">Save</button>
              <button type="button" @click="editingUser = null" class="btn-secondary">Cancel</button>
            </div>
          </form>
        </div>
      </div>
    </div>

    <!-- TAB: Backup & Restore -->
    <div v-if="activeTab === 'backup'" class="tab-content">
      <div class="backup-split">
        <div class="backup-left">
          <!-- Backup -->
          <div class="subsection">
            <h4>Create Backup</h4>
            <p class="section-desc">Export all server configuration, DNS zones, records, blocklist settings, and user accounts to a single file.</p>
            <div class="backup-includes">
              <span class="backup-tag">Settings</span>
              <span class="backup-tag">DNS Zones</span>
              <span class="backup-tag">DNS Records</span>
              <span class="backup-tag">Blocklist Config</span>
              <span class="backup-tag">User Accounts</span>
              <span class="backup-tag">DNSSEC Keys</span>
              <span class="backup-tag">ACME Config</span>
              <span class="backup-tag">Network Protection</span>
            </div>
            <button @click="createBackup" class="btn-primary" style="margin-top:12px">Download Backup</button>
            <div v-if="backupMsg" class="msg-success" style="margin-top:8px">{{ backupMsg }}</div>
          </div>

          <!-- Restore -->
          <div class="subsection" style="margin-top:20px">
            <h4>Restore from Backup</h4>
            <p class="section-desc">Upload a backup file to restore configuration to this instance. Existing data will be merged (not overwritten).</p>
            <div class="restore-upload">
              <label class="btn-primary upload-btn">
                Select Backup File (.json)
                <input type="file" @change="handleRestoreFile" style="display:none" accept=".json" />
              </label>
            </div>
            <div v-if="restoreMsg" :class="restoreMsgType === 'error' ? 'msg-error' : 'msg-success'" style="margin-top:8px">{{ restoreMsg }}</div>
          </div>
        </div>

        <div class="backup-right">
          <div class="how-it-works">
            <h4>How It Works</h4>
            <div class="hiw-section">
              <h5>Backup</h5>
              <p>Downloads a JSON file containing your complete server configuration. Use this to:</p>
              <ul>
                <li>Migrate to a new server</li>
                <li>Create a snapshot before major changes</li>
                <li>Set up a secondary instance with same config</li>
                <li>Disaster recovery</li>
              </ul>
              <p><strong>Note:</strong> Query logs and blocklist domain data are NOT included (they're too large and rebuild automatically).</p>
            </div>
            <div class="hiw-section">
              <h5>Restore</h5>
              <p>Upload a previously exported backup file. The restore process:</p>
              <ol>
                <li>Reads the backup file</li>
                <li>Restores all settings</li>
                <li>Creates zones and DNS records</li>
                <li>Existing zones with same name are skipped</li>
              </ol>
              <p><strong>Note:</strong> User passwords are not included in backups for security. Users will need to reset passwords after restore.</p>
            </div>
          </div>
        </div>
      </div>
    </div>

  </div>
</template>

<script setup lang="ts">
import { ref, computed, inject, onMounted, nextTick } from 'vue'
import axios from 'axios'
import QRCode from 'qrcode'
import { currentUser } from '../auth'

const confirm = inject('confirm') as (opts: any) => Promise<boolean>
const requestRestart = inject('requestRestart') as () => void

// --- Tabs ---
const activeTab = ref('identity')
const settingsTabs = [
  { id: 'identity', label: 'Server Identity' },
  { id: 'cluster', label: 'Clustering' },
  { id: 'dns', label: 'DNS Services' },
  { id: 'forwarders', label: 'Forwarders' },
  { id: 'certs', label: 'Certificates' },
  { id: 'blockpage', label: 'Block Page' },
  { id: 'logs', label: 'Log Management' },
  { id: 'mail', label: 'Mail' },
  { id: 'users', label: 'Users' },
  { id: 'backup', label: 'Backup & Restore' },
]

// --- Users ---
const users = ref<any[]>([])
const myUser = ref<any>(null)
const editingUser = ref<any>(null)
const mfaSetup = ref<any>(null)
const mfaSetupUser = ref<any>(null)
const mfaVerifyCode = ref('')
const mfaError = ref('')
const qrCanvas = ref<HTMLCanvasElement | null>(null)
const recoveryCodes = ref<string[]>([])
const userFormError = ref('')
const userFormSuccess = ref('')
const currentUsername = currentUser.value?.username || ''
const resetPwUser = ref<any>(null)
const resetPwValue = ref('')
const resetPwConfirm = ref('')
const resetPwError = ref('')

const userForm = ref({ username: '', password: '', first_name: '', last_name: '', email: '', role: 'viewer' })

// --- Fail2Ban & Access Control ---
const f2bSettings = ref({ enabled: true, max_retries: 5, ban_seconds: 900 })
const f2bBanMinutes = ref(15)
const f2bBanned = ref<any[]>([])
const allowedIPs = ref<string[]>([])
const newAllowedIP = ref('')
const mfaEmailEnabled = ref(false)

async function loadFail2Ban() {
  try {
    const { data } = await axios.get('/api/fail2ban')
    f2bSettings.value = data.settings
    f2bBanMinutes.value = Math.round((data.settings.ban_seconds || 900) / 60)
    f2bBanned.value = data.banned || []
    allowedIPs.value = data.allowed_ips || []
  } catch {}
}

function toggleFail2Ban() {
  f2bSettings.value.enabled = !f2bSettings.value.enabled
  saveFail2Ban()
}

async function saveFail2Ban() {
  await axios.put('/api/fail2ban/settings', {
    enabled: f2bSettings.value.enabled,
    max_retries: f2bSettings.value.max_retries,
    ban_seconds: f2bBanMinutes.value * 60,
  })
}

async function unbanIP(ip: string) {
  await axios.delete(`/api/fail2ban/unban/${ip}`)
  loadFail2Ban()
}

async function addAllowedIP() {
  if (!newAllowedIP.value) return
  const updated = [...allowedIPs.value, newAllowedIP.value.trim()]
  await axios.put('/api/fail2ban/allowed-ips', { ips: updated })
  newAllowedIP.value = ''
  loadFail2Ban()
}

async function removeAllowedIP(ip: string) {
  const updated = allowedIPs.value.filter(i => i !== ip)
  await axios.put('/api/fail2ban/allowed-ips', { ips: updated })
  loadFail2Ban()
}

function formatRelative(d: string): string {
  const ms = new Date(d).getTime() - Date.now()
  if (ms <= 0) return 'expired'
  const min = Math.round(ms / 60000)
  return min > 60 ? `${Math.round(min/60)}h ${min%60}m` : `${min}m`
}

async function loadUsers() {
  try { const { data } = await axios.get('/api/users'); users.value = data } catch {}
}
async function loadMe() {
  try { const { data } = await axios.get('/api/auth/me'); myUser.value = data } catch {}
}
async function createUser() {
  userFormError.value = ''; userFormSuccess.value = ''
  try {
    await axios.post('/api/users', userForm.value)
    userFormSuccess.value = `User '${userForm.value.username}' created`
    userForm.value = { username: '', password: '', first_name: '', last_name: '', email: '', role: 'viewer' }
    loadUsers()
  } catch (e: any) { userFormError.value = e.response?.data?.error || 'Failed' }
}
function editUser(u: any) { editingUser.value = { ...u } }
async function saveUserEdit() {
  await axios.put(`/api/users/${editingUser.value.id}`, editingUser.value)
  editingUser.value = null; loadUsers()
}

// Reset password modal
function openResetPw(u: any) {
  resetPwUser.value = u
  resetPwValue.value = ''
  resetPwConfirm.value = ''
  resetPwError.value = ''
}
async function submitResetPw() {
  if (resetPwValue.value !== resetPwConfirm.value) {
    resetPwError.value = 'Passwords do not match'; return
  }
  try {
    await axios.put(`/api/users/${resetPwUser.value.id}/password`, { new_password: resetPwValue.value })
    resetPwUser.value = null
  } catch (e: any) { resetPwError.value = e.response?.data?.error || 'Failed' }
}

async function deleteUser(u: any) {
  if (!await confirm({ title: 'Delete User', message: `Delete user "${u.username}"?`, confirmText: 'Delete', danger: true })) return
  await axios.delete(`/api/users/${u.id}`); loadUsers()
}

// Per-user MFA
async function setupUserMFA(u: any) {
  mfaSetupUser.value = u
  mfaSetup.value = null
  mfaVerifyCode.value = ''
  mfaError.value = ''
  try {
    const { data } = await axios.post('/api/auth/mfa/setup')
    mfaSetup.value = data
    nextTick(() => {
      if (qrCanvas.value && mfaSetup.value?.uri) {
        QRCode.toCanvas(qrCanvas.value, mfaSetup.value.uri, {
          width: 200,
          margin: 2,
          color: { dark: '#1e293b', light: '#ffffff' }
        })
      }
    })
  } catch {}
}
async function enableMFA() {
  mfaError.value = ''
  try {
    const { data } = await axios.post('/api/auth/mfa/enable', { code: mfaVerifyCode.value })
    if (data.recovery_codes) {
      recoveryCodes.value = data.recovery_codes
    }
    mfaSetup.value = null; mfaSetupUser.value = null; mfaVerifyCode.value = ''
    loadUsers(); loadMe()
  } catch (e: any) { mfaError.value = e.response?.data?.error || 'Invalid code' }
}

function copyRecoveryCodes() {
  navigator.clipboard.writeText(recoveryCodes.value.join('\n'))
}
async function disableUserMFA(u: any) {
  if (!await confirm({ title: 'Disable MFA', message: `Disable TOTP for "${u.username}"?`, confirmText: 'Disable', danger: true })) return
  await axios.delete('/api/auth/mfa')
  loadUsers(); loadMe()
}

// --- State ---
const hostname = ref('ns1.dnssupreme.local')
const primaryDomain = ref('dnssupreme.local')
const hostnameMsg = ref('')
const cluster = ref<any>({
  enabled: false, role: 'standalone', peer_address: '', peer_port: 53,
  shared_secret: '', sync_zones: true, sync_blocklists: true, sync_settings: false, peers: [],
})
const clusterMsg = ref('')
const clusterPeerStatus = ref('unknown')
const clusterLatency = ref(0)
const clusterError = ref('')

async function testClusterPeer() {
  clusterPeerStatus.value = 'checking'
  clusterError.value = ''
  clusterLatency.value = 0
  try {
    const { data } = await axios.post('/api/settings/cluster/test')
    clusterPeerStatus.value = data.status
    clusterLatency.value = data.latency_ms || 0
    if (data.error) clusterError.value = data.error
  } catch (e: any) {
    clusterPeerStatus.value = 'offline'
    clusterError.value = e.response?.data?.error || 'Connection test failed'
  }
}

const protocols = ref([
  { id: 'udp', name: 'DNS (UDP)', port: 'Port 53', desc: 'Standard DNS over UDP — fastest, most common', enabled: true },
  { id: 'tcp', name: 'DNS (TCP)', port: 'Port 53', desc: 'Standard DNS over TCP — for large responses', enabled: true },
  { id: 'dot', name: 'DNS-over-TLS', port: 'Port 853', desc: 'Encrypted DNS using TLS (RFC 7858)', enabled: true },
  { id: 'doh', name: 'DNS-over-HTTPS', port: 'Port 443', desc: 'Encrypted DNS over HTTPS (RFC 8484) — shared with block page via /dns-query', enabled: true },
  { id: 'doq', name: 'DNS-over-QUIC', port: 'Port 853/UDP', desc: 'Encrypted DNS over QUIC (RFC 9250)', enabled: true },
])

const serverSettings = ref({
  ipv4: '0.0.0.0', ipv6: '::', ipv6Enabled: true,
  cacheSize: 10000, defaultTTL: 3600, minTTL: 10, maxTTL: 86400,
  mgmtHTTPS: false,
})
const serverMsg = ref('')
const mgmtHttpsOriginal = ref(false)
const mgmtHttpsChanged = computed(() => serverSettings.value.mgmtHTTPS !== mgmtHttpsOriginal.value)

const forwarders = ref<any[]>([])
const newForwarder = ref('')

const upstreamProviders = [
  {
    name: 'Cloudflare', privacy: 'No logging',
    protocols: [
      { label: 'DNS', type: 'dns', addr: '1.1.1.1:53' },
      { label: 'DNS', type: 'dns', addr: '1.0.0.1:53' },
      { label: 'DoT', type: 'dot', addr: 'tls://1dot1dot1dot1.cloudflare-dns.com' },
      { label: 'DoH', type: 'doh', addr: 'https://cloudflare-dns.com/dns-query' },
    ]
  },
  {
    name: 'Google', privacy: 'Logged 24-48h',
    protocols: [
      { label: 'DNS', type: 'dns', addr: '8.8.8.8:53' },
      { label: 'DNS', type: 'dns', addr: '8.8.4.4:53' },
      { label: 'DoT', type: 'dot', addr: 'tls://dns.google' },
      { label: 'DoH', type: 'doh', addr: 'https://dns.google/dns-query' },
    ]
  },
  {
    name: 'Quad9', privacy: 'No logging, malware blocking',
    protocols: [
      { label: 'DNS', type: 'dns', addr: '9.9.9.9:53' },
      { label: 'DNS', type: 'dns', addr: '149.112.112.112:53' },
      { label: 'DoT', type: 'dot', addr: 'tls://dns.quad9.net' },
      { label: 'DoH', type: 'doh', addr: 'https://dns.quad9.net/dns-query' },
    ]
  },
  {
    name: 'AdGuard DNS', privacy: 'No logging, ad blocking',
    protocols: [
      { label: 'DNS', type: 'dns', addr: '94.140.14.14:53' },
      { label: 'DNS', type: 'dns', addr: '94.140.15.15:53' },
      { label: 'DoT', type: 'dot', addr: 'tls://dns.adguard-dns.com' },
      { label: 'DoH', type: 'doh', addr: 'https://dns.adguard-dns.com/dns-query' },
      { label: 'DoQ', type: 'doq', addr: 'quic://dns.adguard-dns.com' },
    ]
  },
  {
    name: 'OpenDNS (Cisco)', privacy: 'Logged',
    protocols: [
      { label: 'DNS', type: 'dns', addr: '208.67.222.222:53' },
      { label: 'DNS', type: 'dns', addr: '208.67.220.220:53' },
      { label: 'DoH', type: 'doh', addr: 'https://doh.opendns.com/dns-query' },
    ]
  },
  {
    name: 'Mullvad', privacy: 'No logging, privacy-focused',
    protocols: [
      { label: 'DoH', type: 'doh', addr: 'https://dns.mullvad.net/dns-query' },
      { label: 'DoT', type: 'dot', addr: 'tls://dns.mullvad.net' },
    ]
  },
  {
    name: 'NextDNS', privacy: 'Configurable logging',
    protocols: [
      { label: 'DoH', type: 'doh', addr: 'https://dns.nextdns.io' },
      { label: 'DoT', type: 'dot', addr: 'tls://dns.nextdns.io' },
      { label: 'DoQ', type: 'doq', addr: 'quic://dns.nextdns.io' },
    ]
  },
  {
    name: 'Control D', privacy: 'Configurable',
    protocols: [
      { label: 'DoH', type: 'doh', addr: 'https://freedns.controld.com/p0' },
      { label: 'DoT', type: 'dot', addr: 'tls://p0.freedns.controld.com' },
      { label: 'DoQ', type: 'doq', addr: 'quic://p0.freedns.controld.com' },
    ]
  },
]

function isForwarderAdded(addr: string): boolean {
  return forwarders.value.some((f: any) => f.address === addr)
}

async function addForwarderDirect(addr: string) {
  if (isForwarderAdded(addr)) return
  const current = forwarders.value.map((f: any) => f.address)
  current.push(addr)
  await axios.put('/api/settings/forwarders', { forwarders: current })
  loadAll()
}

const dnssecKeys = ref<any[]>([])
const dnssecZone = ref('')

// --- Mail ---
const mailSettings = ref({
  host: '', port: 587, username: '', password: '',
  from: '', fromName: 'DNS Supreme', encryption: 'starttls',
  recipients: ''
})
const mailNotifs = ref({
  securityAlerts: true, userChanges: false, configChanges: false,
  certExpiry: true, certRenewal: false,
  feedErrors: true, highBlockRate: false, diskUsage: false, dnsErrors: false,
  clusterOffline: true, axfrRequests: false,
  dailyReport: false, weeklyReport: false,
})
const mailMsg = ref('')

async function loadMailSettings() {
  try {
    const [cfg, notif] = await Promise.all([
      axios.get('/api/mail/settings'),
      axios.get('/api/mail/notifications'),
    ])
    if (cfg.data.host) mailSettings.value = cfg.data
    mailNotifs.value = { ...mailNotifs.value, ...notif.data }
  } catch {}
}

async function saveMailSettings() {
  mailMsg.value = ''
  try {
    await axios.put('/api/mail/settings', mailSettings.value)
    await axios.put('/api/mail/notifications', mailNotifs.value)
    mailMsg.value = 'Mail settings saved'
    setTimeout(() => mailMsg.value = '', 3000)
  } catch (e: any) {
    mailMsg.value = 'Failed: ' + (e.response?.data?.error || e.message)
  }
}

async function testMail() {
  mailMsg.value = ''
  try {
    const { data } = await axios.post('/api/mail/test', { to: mailSettings.value.from })
    mailMsg.value = `Test email sent to ${data.sent_to}`
    setTimeout(() => mailMsg.value = '', 5000)
  } catch (e: any) {
    mailMsg.value = 'Failed: ' + (e.response?.data?.error || e.message)
  }
}

const certInfo = ref<any>(null)
const certMsg = ref('')
const certReq = ref({
  common_name: '', organization: '', organizational_unit: '',
  country: '', state: '', locality: '', dns_names: [] as string[], validity_days: 365,
})
const certDnsNamesStr = ref('')
const certDeleteConfirmText = ref('')
const certDeleteShow = ref(false)

const certExpiryDays = computed(() => {
  if (!certInfo.value?.not_after) return 999
  const diff = new Date(certInfo.value.not_after).getTime() - Date.now()
  return Math.floor(diff / (1000 * 60 * 60 * 24))
})
const certExpired = computed(() => certExpiryDays.value <= 0)
const certExpiryClass = computed(() => {
  if (certExpired.value) return 'expired'
  if (certExpiryDays.value <= 30) return 'warning'
  return 'valid'
})

const certMode = ref('self-signed')
const acmeDomain = ref('')
const acmeAutoRenew = ref(true)
const acmeStatus = ref<any>(null)
const acmeDnsProvider = ref('local')
const acmeCloudflareToken = ref('')
const acmeProvider = ref('letsencrypt')
const acmeEmail = ref('')
const acmeUrl = ref('')
const acmeChallenge = ref('dns-01')
const acmeMsg = ref('')

async function exportCert(format: string, domain?: string) {
  const params = new URLSearchParams({ format })
  if (domain) params.set('domain', domain)
  try {
    const { data, headers } = await axios.get(`/api/certs/export?${params}`, { responseType: 'blob' })
    const disposition = headers['content-disposition'] || ''
    const match = disposition.match(/filename=(.+)/)
    const filename = match ? match[1] : (format === 'der' ? 'dns-supreme-ca.crt' : 'dns-supreme-ca.pem')
    const url = URL.createObjectURL(data)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  } catch (e: any) {
    certMsg.value = e.response?.data?.error || 'Failed to export certificate'
  }
}

async function loadAcmeConfig() {
  try {
    const { data } = await axios.get('/api/acme/config')
    if (data.provider) acmeProvider.value = data.provider
    if (data.email) acmeEmail.value = data.email
    if (data.url) acmeUrl.value = data.url
    if (data.challenge) acmeChallenge.value = data.challenge
    if (data.dns_provider) acmeDnsProvider.value = data.dns_provider
    if (data.cloudflare_token) acmeCloudflareToken.value = data.cloudflare_token
  } catch {}
}

async function saveAcme() {
  acmeMsg.value = ''
  try {
    await axios.put('/api/acme/config', {
      provider: acmeProvider.value, email: acmeEmail.value,
      url: acmeUrl.value, challenge: acmeChallenge.value,
      dns_provider: acmeDnsProvider.value, cloudflare_token: acmeCloudflareToken.value,
    })
    acmeMsg.value = 'ACME settings saved'
    setTimeout(() => acmeMsg.value = '', 3000)
  } catch (e: any) { acmeMsg.value = 'Failed: ' + (e.response?.data?.error || e.message) }
}

const acmeRequesting = ref(false)

async function requestAcmeCert() {
  const domain = acmeDomain.value
  if (!domain || !acmeEmail.value) return
  acmeRequesting.value = true
  acmeMsg.value = ''
  acmeStatus.value = { status: 'pending', domain }
  try {
    await saveAcme()
    await axios.post('/api/acme/request', { domain })
    acmeMsg.value = `Certificate request started for ${domain}. Waiting for DNS validation...`
    pollAcmeStatus(domain)
  } catch (e: any) {
    acmeMsg.value = 'Failed: ' + (e.response?.data?.error || e.message)
    acmeRequesting.value = false
    acmeStatus.value = { status: 'failed', domain, error: acmeMsg.value }
  }
}

async function pollAcmeStatus(domain: string) {
  for (let i = 0; i < 60; i++) {
    await new Promise(r => setTimeout(r, 5000))
    try {
      const { data } = await axios.get(`/api/acme/status/${domain}`)
      acmeStatus.value = data
      if (data.status === 'issued') {
        acmeMsg.value = 'Certificate issued! Click "Apply & Restart" to use it.'
        acmeRequesting.value = false
        return
      } else if (data.status === 'failed') {
        acmeMsg.value = ''
        acmeRequesting.value = false
        return
      }
    } catch { break }
  }
  acmeRequesting.value = false
}

async function applyAcmeCert() {
  acmeMsg.value = 'Applying certificate and restarting...'
  try {
    await axios.post('/api/restart')
  } catch {}
  await waitForServer()
  acmeMsg.value = 'Certificate applied. Server restarted.'
  loadAll()
  setTimeout(() => acmeMsg.value = '', 5000)
}

async function loadAcmeStatus() {
  if (!acmeDomain.value) return
  try {
    const { data } = await axios.get(`/api/acme/status/${acmeDomain.value}`)
    if (data.status && data.status !== 'none') acmeStatus.value = data
  } catch {}
}
const certZones = ref<any[]>([])

async function loadCertZones() {
  try {
    const { data } = await axios.get('/api/zones')
    const zones = (data || []).map((z: any) => ({ name: z.name, has_cert: false }))
    // Check which zones have certs
    try {
      const { data: certData } = await axios.get('/api/certs/zones')
      for (const z of zones) {
        z.has_cert = certData?.includes(z.name)
      }
    } catch {}
    certZones.value = zones
  } catch {}
}

async function generateZoneCert(zoneName: string) {
  certMsg.value = ''
  try {
    const { data } = await axios.post('/api/certs/generate', { domain: zoneName })
    certMsg.value = data.message || `Certificate generated for ${zoneName}`
    requestRestart()
    setTimeout(() => loadCertZones(), 1000)
    setTimeout(() => certMsg.value = '', 5000)
  } catch (e: any) {
    certMsg.value = 'Failed: ' + (e.response?.data?.error || e.message)
  }
}

const blockPageHTML = ref('')
const bpMsg = ref('')
const bpDomain = ref('')
const bpDomainMsg = ref('')
const bpRedirectURL = ref('')
const bpRedirectMsg = ref('')
const bpPrefix = ref('denied')
const bpZone = ref('')
const bpZones = ref<string[]>([])
const bpSetupLoading = ref(false)
const bpCertStatus = ref('none') // none, requesting, issued, failed
const bpMode = ref('visual')
const bpLogo = ref('')
const bpHeading = ref('Access Blocked')
const bpMessage = ref('Access to this page has been blocked by your network administrator.')
const bpFooter = ref('Protected by DNS Supreme')
const bpDescription = ref('')
const bpColor = ref('#ef4444')
const logoUploading = ref(false)

const bpPreviewHTML = computed(() => {
  const html = blockPageHTML.value || generateVisualHTML()
  return html.replace(/\{\{\.Domain\}\}/g, 'example-blocked.com').replace(/\{\{\.Reason\}\}/g, '[ads] stevenblack-hosts')
})

function generateVisualHTML(): string {
  const logo = bpLogo.value ? `<img src="${bpLogo.value}" alt="Logo" style="max-height:48px;margin-bottom:16px">` : ''
  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Blocked</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0f172a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#e2e8f0}
.card{background:#1e293b;border:1px solid #334155;border-radius:16px;padding:48px;max-width:480px;width:90%;text-align:center;box-shadow:0 16px 48px rgba(0,0,0,0.3)}
.logo{margin-bottom:16px}
.icon{font-size:48px;margin-bottom:16px;color:${bpColor.value}}
h1{font-size:1.5rem;color:#f1f5f9;margin-bottom:12px}
.message{color:#94a3b8;font-size:0.95rem;line-height:1.6;margin-bottom:0}
.opt-message{color:#94a3b8;font-size:0.95rem;line-height:1.6;margin-top:12px}
.msg-block{margin-bottom:20px}
.domain{background:#0f172a;border:1px solid #334155;border-radius:8px;padding:10px 16px;font-family:monospace;font-size:0.9rem;color:${bpColor.value};margin-bottom:8px;word-break:break-all}
.reason{color:#64748b;font-size:0.8rem;margin-bottom:20px}
.footer{color:#475569;font-size:0.75rem;padding-top:16px;border-top:1px solid #334155}
</style></head><body>
<div class="card">
  <div class="logo">${logo}</div>
  <div class="icon">&#x26D4;</div>
  <h1>${bpHeading.value || 'Access Blocked'}</h1>
  <div class="msg-block">
    <p class="message">${bpMessage.value || ''}</p>
    ${bpDescription.value ? `<p class="opt-message">${bpDescription.value}</p>` : ''}
  </div>
  <div class="domain">{{.Domain}}</div>
  <p class="reason">Reason: {{.Reason}}</p>
  ${bpFooter.value ? `<div class="footer">${bpFooter.value}</div>` : ''}
</div>
</body></html>`
}

async function uploadLogo(event: Event) {
  const input = event.target as HTMLInputElement
  if (!input.files?.length) return

  const file = input.files[0]
  if (file.size > 2 * 1024 * 1024) {
    bpMsg.value = 'Logo file too large (max 2MB)'
    setTimeout(() => bpMsg.value = '', 3000)
    return
  }

  logoUploading.value = true
  try {
    const formData = new FormData()
    formData.append('logo', file)
    const { data } = await axios.post('/api/settings/blockpage/upload-logo', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
    bpLogo.value = data.url
    updateBpFromVisual()
    bpMsg.value = 'Logo uploaded'
    setTimeout(() => bpMsg.value = '', 3000)
  } catch (e: any) {
    bpMsg.value = 'Upload failed: ' + (e.response?.data?.error || e.message)
    setTimeout(() => bpMsg.value = '', 3000)
  } finally {
    logoUploading.value = false
    input.value = '' // reset file input
  }
}

function updateBpFromVisual() {
  blockPageHTML.value = generateVisualHTML()
}

function resetBlockPage() {
  bpLogo.value = ''
  bpHeading.value = 'Access Blocked'
  bpMessage.value = 'Access to this page has been blocked by your network administrator.'
  bpDescription.value = ''
  bpFooter.value = 'Protected by DNS Supreme'
  bpColor.value = '#ef4444'
  blockPageHTML.value = ''
  bpMode.value = 'visual'
  saveBlockPage()
}

const logRetention = ref({ days: 30, autoCleanup: true })
const logStats = ref<any>(null)
const logMsg = ref('')


// --- Load ---
async function loadAll() {
  const [fw, dk, certs, bp, bpd, bpr, ss, hn, pd, cl, ls, lr] = await Promise.all([
    axios.get('/api/settings/forwarders'),
    axios.get('/api/dnssec'),
    axios.get('/api/certs'),
    axios.get('/api/settings/blockpage'),
    axios.get('/api/settings/blockpage/domain'),
    axios.get('/api/settings/blockpage/redirect'),
    axios.get('/api/settings/server'),
    axios.get('/api/settings/hostname'),
    axios.get('/api/settings/primary-domain'),
    axios.get('/api/settings/cluster'),
    axios.get('/api/log-management/stats'),
    axios.get('/api/log-management/settings'),
  ])
  forwarders.value = fw.data || []
  dnssecKeys.value = dk.data || []
  certInfo.value = certs.data
  blockPageHTML.value = bp.data.html || ''
  bpDomain.value = bpd.data.domain || ''
  bpRedirectURL.value = bpr.data.redirect_url || ''
  if (bp.data.settings) {
    const s = bp.data.settings
    if (s.logo) bpLogo.value = s.logo
    if (s.heading) bpHeading.value = s.heading
    if (s.message) bpMessage.value = s.message
    if (s.footer) bpFooter.value = s.footer
    if (s.description) bpDescription.value = s.description
    if (s.color) bpColor.value = s.color
  }
  hostname.value = hn.data.hostname || 'ns1.dnssupreme.local'
  primaryDomain.value = pd.data.domain || 'dnssupreme.local'
  cluster.value = cl.data || cluster.value
  logStats.value = ls.data
  logRetention.value.days = lr.data.retention_days || 30
  logRetention.value.autoCleanup = lr.data.auto_cleanup ?? true

  // Map server settings
  if (ss.data.protocols) {
    protocols.value.forEach(p => { if (p.id in ss.data.protocols) p.enabled = ss.data.protocols[p.id] })
  }
  if (ss.data.listen_addresses) {
    serverSettings.value.ipv4 = ss.data.listen_addresses.ipv4 || '0.0.0.0'
    serverSettings.value.ipv6 = ss.data.listen_addresses.ipv6 || '::'
  }
  serverSettings.value.ipv6Enabled = ss.data.ipv6_enabled ?? true
  serverSettings.value.cacheSize = ss.data.cache_size || 10000
  serverSettings.value.defaultTTL = ss.data.default_ttl || 3600
  serverSettings.value.minTTL = ss.data.min_ttl || 10
  serverSettings.value.maxTTL = ss.data.max_ttl || 86400
  serverSettings.value.mgmtHTTPS = ss.data.management_https || false
  mgmtHttpsOriginal.value = serverSettings.value.mgmtHTTPS
}

async function saveServerSettings() {
  serverMsg.value = ''
  const prots: Record<string, boolean> = {}
  protocols.value.forEach(p => prots[p.id] = p.enabled)
  await axios.put('/api/settings/server', {
    protocols: prots,
    listen_addresses: { ipv4: serverSettings.value.ipv4, ipv6: serverSettings.value.ipv6 },
    ipv6_enabled: serverSettings.value.ipv6Enabled,
    cache_size: serverSettings.value.cacheSize,
    default_ttl: serverSettings.value.defaultTTL,
    min_ttl: serverSettings.value.minTTL,
    max_ttl: serverSettings.value.maxTTL,
    management_https: serverSettings.value.mgmtHTTPS,
  })
  serverMsg.value = 'Settings saved. Some changes require a restart.'
  setTimeout(() => serverMsg.value = '', 4000)
}

async function applyMgmtHttps() {
  await saveServerSettings()
  mgmtHttpsOriginal.value = serverSettings.value.mgmtHTTPS
  serverMsg.value = 'Restarting server...'
  try {
    await axios.post('/api/restart')
  } catch {}
  // Wait for server to come back
  await waitForServer()
  serverMsg.value = serverSettings.value.mgmtHTTPS
    ? 'HTTPS enabled. Panel available at https://...:53443.'
    : 'HTTPS disabled. Server restarted.'
  setTimeout(() => serverMsg.value = '', 6000)
}

async function waitForServer() {
  for (let i = 0; i < 30; i++) {
    await new Promise(r => setTimeout(r, 2000))
    try {
      await axios.get('/api/health')
      return
    } catch {}
  }
}

function cancelMgmtHttps() {
  serverSettings.value.mgmtHTTPS = mgmtHttpsOriginal.value
}

async function saveIdentity() {
  hostnameMsg.value = ''
  await Promise.all([
    axios.put('/api/settings/hostname', { hostname: hostname.value }),
    axios.put('/api/settings/primary-domain', { domain: primaryDomain.value }),
  ])
  hostnameMsg.value = 'Identity saved. Zone auto-created if new.'
  setTimeout(() => hostnameMsg.value = '', 4000)
}

function setClusterRole(role: string) {
  cluster.value.role = role
  cluster.value.enabled = role !== 'standalone'
  if (role === 'standalone') saveCluster()
}

async function saveCluster() {
  clusterMsg.value = ''
  const { data } = await axios.put('/api/settings/cluster', cluster.value)
  clusterMsg.value = data.message || 'Saved'
  setTimeout(() => clusterMsg.value = '', 4000)
}

// --- Log Management ---
async function saveLogRetention() {
  await axios.put('/api/log-management/settings', {
    retention_days: logRetention.value.days,
    auto_cleanup: logRetention.value.autoCleanup,
  })
  logMsg.value = 'Retention settings saved'
  setTimeout(() => logMsg.value = '', 3000)
}

function exportLogs(days: number) {
  window.open(`/api/log-management/export?days=${days}`, '_blank')
}

async function deleteOldLogs() {
  // Use retention days as default
  const d = logRetention.value.days
  if (!await confirm({ title: 'Delete Old Logs', message: `Delete all query logs older than ${d} days?`, confirmText: 'Delete', danger: true })) return
  const { data } = await axios.delete(`/api/log-management/older-than?days=${d}`)
  logMsg.value = `Deleted ${data.deleted?.toLocaleString()} log entries`
  loadAll()
  setTimeout(() => logMsg.value = '', 5000)
}

async function deleteAllLogs() {
  if (!await confirm({ title: 'Delete All Logs', message: 'Delete ALL query logs? All log data will be permanently deleted. This cannot be undone.', confirmText: 'Delete All', danger: true })) return
  const { data } = await axios.delete('/api/log-management/all')
  logMsg.value = `Deleted ${data.deleted?.toLocaleString()} log entries`
  loadAll()
  setTimeout(() => logMsg.value = '', 5000)
}

// --- Forwarders ---
async function addForwarder() {
  if (!newForwarder.value) return
  let addr = newForwarder.value.trim()
  if (!addr.includes(':')) addr += ':53'
  const current = forwarders.value.map((f: any) => f.address)
  current.push(addr)
  await axios.put('/api/settings/forwarders', { forwarders: current })
  newForwarder.value = ''
  loadAll()
}

async function removeForwarder(index: number) {
  const current = forwarders.value.map((f: any) => f.address)
  current.splice(index, 1)
  await axios.put('/api/settings/forwarders', { forwarders: current })
  loadAll()
}

// --- DNSSEC ---
async function generateDNSSEC() {
  await axios.post('/api/dnssec/generate', { zone_name: dnssecZone.value })
  dnssecZone.value = ''
  loadAll()
}

async function toggleDNSSEC(key: any) {
  await axios.put(`/api/dnssec/${key.zone_name}`, { enabled: !key.enabled })
  loadAll()
}

async function removeDNSSEC(zone: string) {
  if (!await confirm({ title: 'Remove DNSSEC Key', message: `Remove DNSSEC key for ${zone}? This will disable zone signing.`, confirmText: 'Remove', danger: true })) return
  await axios.delete(`/api/dnssec/${zone}`)
  loadAll()
}

function copyText(text: string) {
  navigator.clipboard.writeText(text)
}

// --- Certificates ---
async function generateCert() {
  certMsg.value = ''
  const req = { ...certReq.value }
  if (certDnsNamesStr.value) {
    req.dns_names = certDnsNamesStr.value.split(',').map((s: string) => s.trim()).filter(Boolean)
  }
  if (!req.common_name) req.common_name = hostname.value || 'dns-supreme'
  const { data } = await axios.post('/api/certs/generate', req)
  certMsg.value = data.message
  loadAll()
  requestRestart()
  setTimeout(() => certMsg.value = '', 5000)
}

async function reissueCert() {
  if (!await confirm({ title: 'Re-issue Certificate', message: 'Generate a new certificate with the same parameters? The current certificate will be replaced.', confirmText: 'Re-issue', danger: false })) return
  generateCert()
}

async function deleteCert() {
  if (!await confirm({ title: 'Delete Certificate', message: 'Are you sure you want to delete the server certificate? All encrypted protocols (DoT, DoH, DoQ) will stop working until a new certificate is generated.', confirmText: 'Continue', danger: true })) return
  // Second confirmation: type DELETE
  certDeleteShow.value = true
  certDeleteConfirmText.value = ''
}

async function confirmDeleteCert() {
  certDeleteShow.value = false
  try {
    await axios.delete('/api/certs')
    certMsg.value = 'Certificate deleted. Generate a new one or upload.'
    certInfo.value = null
    loadAll()
  } catch (e: any) {
    certMsg.value = e.response?.data?.error || 'Failed to delete certificate'
  }
}

async function handleCertUpload(e: Event) {
  const input = e.target as HTMLInputElement
  if (!input.files?.length) return
  const certFile = input.files[0]
  // Store cert file, prompt for key file next
  certUploadCert.value = certFile
  certUploadShow.value = true
}

const certUploadShow = ref(false)
const certUploadCert = ref<File | null>(null)
const certUploadKeyText = ref('')

async function submitCertUpload() {
  if (!certUploadCert.value || !certUploadKeyText.value) return
  const formData = new FormData()
  formData.append('cert', certUploadCert.value)
  formData.append('key', new Blob([certUploadKeyText.value], { type: 'text/plain' }), 'server.key')
  certMsg.value = ''
  try {
    const { data } = await axios.post('/api/certs/upload', formData)
    certMsg.value = data.message
    certUploadShow.value = false
    certUploadKeyText.value = ''
    loadAll()
    requestRestart()
  } catch (err: any) {
    certMsg.value = 'Upload failed: ' + (err.response?.data?.error || err.message)
  }
}

function formatDate(d: string) {
  return new Date(d).toLocaleDateString([], { year: 'numeric', month: 'long', day: 'numeric' })
}

// --- Block Page ---
async function loadBpZones() {
  try {
    const { data } = await axios.get('/api/zones')
    bpZones.value = (data || []).map((z: any) => z.name)
  } catch {}
}

async function setupBpDomain() {
  if (!bpPrefix.value || !bpZone.value) return
  bpSetupLoading.value = true
  bpDomainMsg.value = ''
  try {
    const { data } = await axios.post('/api/settings/blockpage/setup-domain', {
      prefix: bpPrefix.value,
      zone: bpZone.value,
    })
    bpDomain.value = data.domain
    bpRedirectURL.value = data.redirect_url
    if (data.cert === 'loaded') {
      bpCertStatus.value = 'issued'
      bpDomainMsg.value = 'Block page configured with HTTPS certificate'
    } else if (data.cert === 'requesting') {
      bpCertStatus.value = 'requesting'
      bpDomainMsg.value = 'Domain configured, requesting TLS certificate...'
      pollBpCertStatus(data.domain)
    } else {
      bpCertStatus.value = 'none'
      bpDomainMsg.value = 'Domain configured (no ACME email set — configure in Certificates tab for HTTPS)'
    }
  } catch (e: any) {
    bpDomainMsg.value = 'Failed: ' + (e.response?.data?.error || e.message)
  } finally {
    bpSetupLoading.value = false
  }
}

async function clearBpDomain() {
  try {
    await axios.put('/api/settings/blockpage/domain', { domain: '' })
    await axios.put('/api/settings/blockpage/redirect', { redirect_url: '' })
    bpDomain.value = ''
    bpRedirectURL.value = ''
    bpPrefix.value = 'denied'
    bpZone.value = ''
    bpCertStatus.value = 'none'
    bpDomainMsg.value = 'Block page domain cleared'
    setTimeout(() => bpDomainMsg.value = '', 3000)
  } catch {}
}

async function pollBpCertStatus(domain: string) {
  for (let i = 0; i < 60; i++) {
    await new Promise(r => setTimeout(r, 5000))
    try {
      const { data } = await axios.get(`/api/acme/status/${domain}`)
      if (data.status === 'issued') {
        bpCertStatus.value = 'issued'
        bpDomainMsg.value = 'TLS certificate issued! Block page now uses HTTPS.'
        // Reload to get updated redirect URL
        const { data: redir } = await axios.get('/api/settings/blockpage/redirect')
        bpRedirectURL.value = redir.redirect_url || ''
        return
      } else if (data.status === 'failed') {
        bpCertStatus.value = 'failed'
        bpDomainMsg.value = 'Certificate request failed: ' + (data.error || 'unknown error')
        return
      }
    } catch { break }
  }
}

async function checkBpCertStatus() {
  if (!bpDomain.value) return
  try {
    const { data } = await axios.get(`/api/acme/status/${bpDomain.value}`)
    bpCertStatus.value = data.status || 'none'
  } catch {
    bpCertStatus.value = 'none'
  }
}

async function saveBlockPageDomain() {
  bpDomainMsg.value = ''
  try {
    await axios.put('/api/settings/blockpage/domain', { domain: bpDomain.value })
    bpDomainMsg.value = bpDomain.value ? 'Block page domain saved' : 'Block page domain cleared'
    setTimeout(() => bpDomainMsg.value = '', 3000)
  } catch (e: any) {
    bpDomainMsg.value = 'Failed: ' + (e.response?.data?.error || e.message)
  }
}

async function saveBlockPageRedirect() {
  bpRedirectMsg.value = ''
  try {
    await axios.put('/api/settings/blockpage/redirect', { redirect_url: bpRedirectURL.value })
    bpRedirectMsg.value = bpRedirectURL.value ? 'Redirect URL saved' : 'Redirect URL cleared'
    setTimeout(() => bpRedirectMsg.value = '', 3000)
  } catch (e: any) {
    bpRedirectMsg.value = 'Failed: ' + (e.response?.data?.error || e.message)
  }
}

async function saveBlockPage() {
  bpMsg.value = ''
  const html = blockPageHTML.value || generateVisualHTML()
  await axios.put('/api/settings/blockpage', {
    html,
    settings: {
      logo: bpLogo.value,
      heading: bpHeading.value,
      message: bpMessage.value,
      footer: bpFooter.value,
      description: bpDescription.value,
      color: bpColor.value,
    }
  })
  bpMsg.value = 'Block page saved'
  setTimeout(() => bpMsg.value = '', 3000)
}

// --- Backup & Restore ---
const backupMsg = ref('')
const restoreMsg = ref('')
const restoreMsgType = ref('success')

async function createBackup() {
  backupMsg.value = 'Generating backup...'
  try {
    const { data, headers } = await axios.get('/api/backup/export', { responseType: 'blob' })
    const disposition = headers['content-disposition'] || ''
    const match = disposition.match(/filename=(.+)/)
    const filename = match ? match[1] : 'dns-supreme-backup.json'
    const url = URL.createObjectURL(data)
    const a = document.createElement('a')
    a.href = url; a.download = filename; a.click()
    URL.revokeObjectURL(url)
    backupMsg.value = 'Backup downloaded!'
    setTimeout(() => backupMsg.value = '', 3000)
  } catch {
    backupMsg.value = 'Failed to create backup'
  }
}

async function handleRestoreFile(e: Event) {
  const input = e.target as HTMLInputElement
  if (!input.files?.length) return
  restoreMsg.value = 'Restoring...'
  restoreMsgType.value = 'success'
  const formData = new FormData()
  formData.append('backup', input.files[0])
  try {
    const { data } = await axios.post('/api/backup/restore', formData)
    restoreMsg.value = data.message || 'Restore complete!'
    loadAll()
  } catch (e: any) {
    restoreMsg.value = e.response?.data?.error || 'Restore failed'
    restoreMsgType.value = 'error'
  }
  input.value = ''
}

onMounted(async () => {
  await loadAll()
  loadUsers(); loadMe(); loadCertZones(); loadFail2Ban(); loadMailSettings(); loadAcmeConfig()
  loadBpZones()
  nextTick(() => loadAcmeStatus())
  // Parse existing bpDomain into prefix + zone
  if (bpDomain.value && bpDomain.value.includes('.')) {
    const dot = bpDomain.value.indexOf('.')
    bpPrefix.value = bpDomain.value.substring(0, dot)
    const zone = bpDomain.value.substring(dot + 1)
    bpZone.value = zone
  }
  checkBpCertStatus()
})
</script>

<style scoped>
.btn-upload {
  display: inline-flex;
  align-items: center;
  padding: 6px 14px;
  background: var(--bg-hover);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text);
  font-size: 0.85rem;
  cursor: pointer;
  white-space: nowrap;
  transition: background 0.15s;
}
.btn-upload:hover {
  background: var(--accent);
  color: #fff;
}
.settings-page h2 { margin-bottom: 16px; font-size: 1.5rem; }

/* Tabs */
.tabs {
  display: flex; gap: 2px; margin-bottom: 20px; background: var(--bg-card);
  border-radius: 10px; padding: 4px; border: 1px solid var(--border); flex-wrap: wrap;
}
.tab-btn {
  padding: 8px 14px; background: transparent; border: none;
  color: var(--text-secondary); border-radius: 8px; cursor: pointer;
  font-size: 0.82rem; font-weight: 500; transition: all 0.15s; white-space: nowrap;
}
.tab-btn:hover { color: var(--text-primary); background: var(--bg-hover); }
.tab-btn.active { background: var(--accent); color: #fff; }
.tab-content { animation: fadeIn 0.15s ease-out; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }

/* Users */
.user-form { display: flex; gap: 8px; flex-wrap: wrap; align-items: flex-end; }
.user-form input, .user-form select {
  padding: 8px 12px; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 6px; color: var(--text-primary); font-size: 0.9rem; flex: 1; min-width: 120px;
}
.user-form input::placeholder { color: var(--text-dim); }
.username { font-weight: 600; color: var(--text-primary); }
.time { color: var(--text-muted); font-size: 0.8rem; white-space: nowrap; }
.actions { display: flex; gap: 6px; }
.btn-sm { padding: 4px 10px; background: var(--bg-hover); border: none; color: var(--text-secondary); border-radius: 4px; cursor: pointer; font-size: 0.8rem; transition: all 0.15s; }
.btn-sm:hover { color: var(--text-primary); }
.btn-sm.warn { color: #f59e0b; }
.btn-sm.warn:hover { background: rgba(245,158,11,0.15); }
.btn-sm.danger { color: #ef4444; }
.btn-sm.danger:hover { background: rgba(239,68,68,0.15); }
.user-badge { padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
.user-badge.admin { background: rgba(139,92,246,0.15); color: #8b5cf6; }
.user-badge.viewer { background: rgba(34,197,94,0.15); color: #22c55e; }
.mfa-on { color: #22c55e; font-weight: 600; font-size: 0.85rem; }
.mfa-off { color: var(--text-muted); font-size: 0.85rem; }
.mfa-status { display: flex; align-items: center; gap: 16px; }
.mfa-setup p { margin-bottom: 8px; }
.recovery-codes-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
}
.recovery-code {
  background: var(--bg);
  border: 1px solid var(--border);
  padding: 8px 12px;
  border-radius: 6px;
  font-size: 0.95rem;
  text-align: center;
  letter-spacing: 1px;
}
.mfa-secret { font-family: monospace; font-size: 1.1rem; color: #f59e0b; background: var(--bg-input); padding: 12px; border-radius: 8px; margin-bottom: 8px; word-break: break-all; }
.mfa-uri { font-size: 0.75rem; color: var(--text-dim); word-break: break-all; margin-bottom: 12px; }
.mfa-verify { display: flex; gap: 8px; }
.mfa-verify input { padding: 8px 12px; background: var(--bg-input); border: 1px solid var(--border); border-radius: 6px; color: var(--text-primary); font-size: 1rem; width: 160px; }
.error-msg { background: rgba(239,68,68,0.1); border: 1px solid #ef4444; color: #ef4444; padding: 8px 12px; border-radius: 6px; font-size: 0.85rem; }
.edit-modal { background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px; padding: 24px; width: 420px; max-width: 90vw; box-shadow: 0 16px 48px rgba(0,0,0,0.3); }
.edit-modal h3 { color: var(--text-primary); margin-bottom: 16px; }

/* Users split */
.users-split { display: grid; grid-template-columns: 3fr 2fr; gap: 20px; align-items: start; }
.users-left { min-width: 0; }
.users-right { display: flex; flex-direction: column; gap: 0; position: sticky; top: 20px; }

.security-card {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 16px;
}
.security-card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; }
.security-card h4 { color: var(--text-primary); font-size: 0.95rem; margin: 0; }

.f2b-banned { margin-top: 8px; }
.f2b-banned h4 { font-size: 0.85rem; color: var(--text-primary); margin-bottom: 6px; }
.f2b-count { font-size: 0.72rem; background: rgba(239,68,68,0.15); color: #ef4444; padding: 1px 6px; border-radius: 8px; margin-left: 4px; }
.f2b-row {
  display: flex; align-items: center; justify-content: space-between; gap: 8px;
  padding: 6px 10px; background: var(--bg-input); border-radius: 6px; margin-bottom: 4px;
}
.f2b-ip { color: var(--text-primary); font-family: monospace; font-size: 0.85rem; }
.f2b-row-info { display: flex; flex-direction: column; }
.f2b-detail { color: var(--text-dim); font-size: 0.72rem; }
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.6); display: flex; align-items: center; justify-content: center; z-index: 100; }

.section {
  background: var(--bg-card); border-radius: 12px; padding: 24px;
  border: 1px solid var(--border); margin-bottom: 20px;
}
.section h3 { color: var(--text-primary); font-size: 1.05rem; margin-bottom: 4px; }
.section-desc { color: var(--text-muted); font-size: 0.88rem; margin-bottom: 16px; line-height: 1.5; }
.section-desc code { color: #f59e0b; background: var(--bg-input); padding: 2px 6px; border-radius: 3px; font-size: 0.8rem; }

/* Shared components */
.add-row { display: flex; gap: 8px; flex-wrap: wrap; }
.add-row input, .add-row select {
  padding: 9px 14px; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 8px; color: var(--text-primary); font-size: 0.9rem; flex: 1; min-width: 150px;
  transition: border-color 0.15s;
}
.add-row input::placeholder { color: var(--text-dim); }

.btn-primary { padding: 9px 20px; background: linear-gradient(135deg, var(--accent), var(--brand-secondary, #818cf8)); color: #fff; border: none; border-radius: 8px; cursor: pointer; font-size: 0.9rem; white-space: nowrap; transition: all 0.15s; }
.btn-primary:hover { opacity: 0.9; }
.btn-primary:disabled { opacity: 0.3; cursor: not-allowed; }
.btn-secondary, .upload-btn { padding: 9px 20px; background: var(--bg-hover); color: var(--text-secondary); border: none; border-radius: 8px; cursor: pointer; font-size: 0.9rem; transition: all 0.15s; }
.btn-secondary:hover, .upload-btn:hover { color: var(--text-primary); }
.btn-text { padding: 9px 16px; background: none; color: var(--text-muted); border: none; cursor: pointer; font-size: 0.85rem; transition: color 0.15s; }
.btn-text:hover { color: var(--text-secondary); }
.btn-text-danger { background: none; border: none; color: #ef4444; cursor: pointer; font-size: 0.8rem; padding: 4px 0; transition: opacity 0.15s; }
.btn-text-danger:hover { opacity: 0.8; }
.btn-copy { padding: 2px 8px; background: var(--bg-hover); color: var(--text-secondary); border: none; border-radius: 4px; cursor: pointer; font-size: 0.75rem; transition: color 0.15s; }
.btn-copy:hover { color: var(--text-primary); }

.section-actions { display: flex; gap: 8px; margin-top: 12px; flex-wrap: wrap; }
.msg-success { background: rgba(34,197,94,0.1); border: 1px solid rgba(34,197,94,0.3); color: #22c55e; padding: 8px 14px; border-radius: 8px; margin-top: 12px; font-size: 0.85rem; }
.empty-small { padding: 16px; text-align: center; color: var(--text-dim); font-size: 0.85rem; }

.detail-row { display: flex; align-items: flex-start; gap: 12px; padding: 6px 0; flex-wrap: wrap; }
.detail-label { color: var(--text-muted); font-size: 0.8rem; min-width: 100px; padding-top: 2px; }
.detail-value { color: var(--text-primary); font-size: 0.85rem; flex: 1; }
.detail-value.mono { font-family: monospace; }
.detail-value.small { font-size: 0.75rem; color: var(--text-secondary); word-break: break-all; }

/* Forwarders */
.forwarders-list { margin-bottom: 12px; }
.forwarder-item {
  display: flex; align-items: center; gap: 12px; padding: 10px 12px;
  background: var(--bg-input); border-radius: 8px; margin-bottom: 6px;
  transition: background 0.15s;
}
.forwarder-num { width: 24px; height: 24px; background: var(--bg-hover); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 0.75rem; color: var(--text-secondary); font-weight: 600; }

/* Forwarders split layout */
.fw-split { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; align-items: start; }
.fw-left { min-width: 0; }
.fw-right {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 20px;
  position: sticky; top: 20px;
}
.fw-right h4 { color: var(--text-primary); font-size: 0.95rem; margin-bottom: 12px; }

.fw-explainer { display: flex; flex-direction: column; gap: 0; }
.fw-explain-step {
  display: flex; gap: 12px; padding: 8px 0;
  border-bottom: 1px solid var(--border);
}
.fw-explain-step:last-child { border-bottom: none; }
.fw-explain-num {
  width: 24px; height: 24px; border-radius: 50%; background: var(--bg-hover);
  display: flex; align-items: center; justify-content: center;
  font-size: 0.72rem; font-weight: 700; color: var(--text-secondary); flex-shrink: 0; margin-top: 2px;
}
.fw-explain-step strong { color: var(--text-primary); font-size: 0.85rem; }
.fw-explain-step .section-desc { font-size: 0.78rem; margin: 0; }

.fw-proto-legend { display: flex; flex-direction: column; gap: 6px; }
.fw-legend-item { display: flex; align-items: center; gap: 8px; color: var(--text-secondary); font-size: 0.8rem; }

/* Upstream presets */
.fw-presets-title { color: var(--text-secondary); font-size: 0.88rem; margin: 16px 0 8px; }
.fw-presets-rows { display: flex; flex-direction: column; gap: 4px; }
.fw-preset-row {
  display: flex; align-items: center; gap: 12px; padding: 8px 12px;
  background: var(--bg-input); border: 1px solid var(--border); border-radius: 8px;
}
.fw-preset-row-info { flex: 1; min-width: 0; }
.fw-preset-name { color: var(--text-primary); font-weight: 600; font-size: 0.88rem; display: block; }
.fw-preset-privacy { color: var(--text-dim); font-size: 0.7rem; }

.fw-preset-protocols { display: flex; gap: 4px; flex-shrink: 0; }
.fw-proto-btn {
  display: flex; align-items: center; gap: 4px; padding: 4px 10px;
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 6px;
  cursor: pointer; transition: all 0.15s; font-size: 0.78rem;
}
.fw-proto-btn:hover:not(:disabled) { border-color: var(--accent); }
.fw-proto-btn:disabled { opacity: 0.4; cursor: default; }
.fw-proto-btn.added { opacity: 0.4; }

.fw-proto-badge {
  padding: 1px 5px; border-radius: 3px; font-size: 0.6rem; font-weight: 700;
  text-transform: uppercase; flex-shrink: 0;
}
.fw-proto-badge.dns { background: rgba(100,116,139,0.2); color: var(--text-secondary); }
.fw-proto-badge.dot { background: rgba(34,197,94,0.15); color: #22c55e; }
.fw-proto-badge.doh { background: rgba(56,189,248,0.15); color: #38bdf8; }
.fw-proto-badge.doq { background: rgba(168,85,247,0.15); color: #a855f7; }

/* Zone certificates */
.cert-zones-list { display: flex; flex-direction: column; gap: 6px; }
.cert-zone-row {
  display: flex; align-items: center; justify-content: space-between; gap: 12px;
  padding: 10px 14px; background: var(--bg-input); border: 1px solid var(--border); border-radius: 8px;
}
.cert-zone-info { display: flex; align-items: center; gap: 12px; }
.cert-zone-name { color: var(--text-primary); font-weight: 600; font-size: 0.9rem; }
.cert-zone-status { font-size: 0.78rem; }
.cert-zone-status.has { color: #22c55e; }
.cert-zone-status.none { color: var(--text-dim); }
/* Block page builder */
.bp-split { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; align-items: start; }
.bp-builder { min-width: 0; }
.bp-mode-switch { display: flex; gap: 2px; margin-bottom: 16px; background: var(--bg-input); border-radius: 8px; padding: 3px; }
.bp-mode-btn {
  flex: 1; padding: 7px 12px; background: transparent; border: none;
  color: var(--text-secondary); border-radius: 6px; cursor: pointer;
  font-size: 0.84rem; transition: all 0.15s;
}
.bp-mode-btn.active { background: var(--accent); color: #fff; }
.bp-visual .field { margin-bottom: 12px; }
.bp-visual textarea { width: 100%; padding: 9px 12px; background: var(--bg-input); border: 1px solid var(--border); border-radius: 8px; color: var(--text-primary); font-size: 0.9rem; resize: vertical; }
.bp-html-mode .code-editor { width: 100%; }

.bp-preview-wrap { position: sticky; top: 20px; }
.bp-preview-wrap h4 { color: var(--text-primary); font-size: 0.9rem; margin-bottom: 8px; }
.bp-preview-frame {
  background: #0f172a; border: 1px solid var(--border); border-radius: 12px;
  overflow: hidden; aspect-ratio: 4/3;
}
.bp-iframe {
  width: 100%; height: 100%; border: none; background: #0f172a;
}

.cert-zone-actions { display: flex; gap: 6px; }

/* Cert export */
.cert-export { border-top: 1px solid var(--border); padding-top: 12px; }
.cert-install-hints { margin-top: 12px; }
.cert-install-hints summary {
  color: var(--accent); font-size: 0.85rem; cursor: pointer; padding: 4px 0;
}
.cert-hint-content { margin-top: 8px; }
.cert-hint-content p {
  color: var(--text-secondary); font-size: 0.82rem; margin-bottom: 8px; line-height: 1.5;
}
.cert-hint-content strong { color: var(--text-primary); }
.cert-hint-content code { color: #f59e0b; background: var(--bg-input); padding: 1px 5px; border-radius: 3px; font-size: 0.78rem; }
.forwarder-info { flex: 1; }
.forwarder-addr { color: var(--text-primary); font-family: monospace; font-size: 0.9rem; }
.forwarder-name { color: var(--text-muted); font-size: 0.8rem; margin-left: 8px; }
.btn-icon-remove { background: none; border: none; color: var(--text-dim); cursor: pointer; font-size: 1rem; padding: 4px 8px; transition: color 0.15s; }
.btn-icon-remove:hover { color: #ef4444; }

/* DNSSEC */
.dnssec-list { margin-bottom: 12px; }
.dnssec-card { background: var(--bg-input); border-radius: 10px; padding: 16px; margin-bottom: 10px; }
.dnssec-header { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
.dnssec-zone { color: var(--text-primary); font-weight: 600; font-size: 1rem; }
.dnssec-algo { color: var(--text-muted); font-size: 0.75rem; background: var(--bg-card); padding: 2px 8px; border-radius: 4px; }
.dnssec-detail { margin-bottom: 8px; }

.toggle-wrap { display: flex; align-items: center; gap: 8px; margin-left: auto; cursor: pointer; }
.toggle { width: 36px; height: 20px; border-radius: 10px; background: var(--text-dim); position: relative; transition: background 0.2s; }
.toggle.on { background: #22c55e; }
.toggle-knob { width: 16px; height: 16px; border-radius: 50%; background: #fff; position: absolute; top: 2px; left: 2px; transition: transform 0.2s; }
.toggle.on .toggle-knob { transform: translateX(16px); }
.toggle-label { font-size: 0.8rem; color: var(--text-muted); }

/* Cert info */
.cert-info { background: var(--bg-input); border-radius: 8px; padding: 14px; margin-bottom: 12px; }

/* Cert split layout */
.certs-split { display: flex; gap: 24px; }
.certs-left { flex: 1; min-width: 0; }
.certs-right { width: 320px; flex-shrink: 0; }
@media (max-width: 900px) { .certs-split { flex-direction: column; } .certs-right { width: 100%; } }

/* How it works panel */
.how-it-works {
  background: var(--bg-input); border: 1px solid var(--border); border-radius: 12px;
  padding: 20px; position: sticky; top: 16px;
}
.how-it-works h4 { color: var(--text-primary); font-size: 1rem; margin-bottom: 16px; }
.hiw-section { margin-bottom: 16px; padding-bottom: 16px; border-bottom: 1px solid var(--border); }
.hiw-section:last-child { margin-bottom: 0; padding-bottom: 0; border-bottom: none; }
.hiw-section h5 { color: var(--accent); font-size: 0.88rem; margin-bottom: 6px; }
.hiw-section p { color: var(--text-secondary); font-size: 0.8rem; line-height: 1.5; margin-bottom: 6px; }
.hiw-section ul, .hiw-section ol { color: var(--text-secondary); font-size: 0.8rem; line-height: 1.6; padding-left: 18px; margin-bottom: 6px; }
.hiw-section li { margin-bottom: 2px; }

/* Cert status bar */
.cert-status-bar {
  display: flex; align-items: center; gap: 8px; padding: 8px 12px;
  border-radius: 6px; margin-bottom: 12px; font-size: 0.85rem; font-weight: 500;
}
.cert-status-bar.valid { background: rgba(34,197,94,0.1); color: #22c55e; }
.cert-status-bar.warning { background: rgba(234,179,8,0.1); color: #eab308; }
.cert-status-bar.expired { background: rgba(239,68,68,0.1); color: #ef4444; }
.cert-status-icon { font-weight: 700; font-size: 0.9rem; }

/* Cert mode toggle */
.cert-mode-toggle {
  display: flex; gap: 0; margin-bottom: 16px; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; width: fit-content;
}
.cert-mode-toggle button {
  padding: 8px 20px; background: var(--bg-input); border: none; color: var(--text-secondary);
  cursor: pointer; font-size: 0.85rem; transition: all 0.15s; border-right: 1px solid var(--border);
}
.cert-mode-toggle button:last-child { border-right: none; }
.cert-mode-toggle button.active { background: var(--accent); color: #fff; }

.cert-active-badge {
  display: inline-flex; align-items: center; gap: 6px; font-size: 0.8rem;
  color: var(--text-muted); margin-bottom: 12px;
}
.cert-active-type {
  padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 0.72rem;
  text-transform: uppercase; background: rgba(56,189,248,0.15); color: #38bdf8;
}

.cert-mode-panel { margin-top: 12px; }

/* ACME status */
.acme-status {
  background: var(--bg-input); border-radius: 8px; padding: 12px; margin-top: 12px;
}
.acme-status-badge {
  padding: 2px 8px; border-radius: 4px; font-size: 0.72rem; font-weight: 600; text-transform: uppercase;
}
.acme-status-badge.active, .acme-status-badge.issued { background: rgba(34,197,94,0.15); color: #22c55e; }
.acme-status-badge.pending { background: rgba(234,179,8,0.15); color: #eab308; }
.acme-status-badge.failed { background: rgba(239,68,68,0.15); color: #ef4444; }

/* Danger outline button */
.btn-danger-outline {
  padding: 8px 16px; background: none; color: #ef4444; border: 1px solid rgba(239,68,68,0.3);
  border-radius: 6px; cursor: pointer; font-size: 0.85rem; transition: all 0.15s;
}
.btn-danger-outline:hover { background: rgba(239,68,68,0.1); border-color: #ef4444; }
.btn-danger { background: #ef4444; color: #fff; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; }
.btn-danger:hover { background: #dc2626; }
.btn-danger:disabled { opacity: 0.3; cursor: not-allowed; }

/* Backup */
.backup-split { display: flex; gap: 24px; }
.backup-left { flex: 1; min-width: 0; }
.backup-right { width: 320px; flex-shrink: 0; }
@media (max-width: 900px) { .backup-split { flex-direction: column; } .backup-right { width: 100%; } }
.backup-includes { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
.backup-tag {
  padding: 4px 10px; background: var(--bg-hover); border: 1px solid var(--border);
  border-radius: 6px; font-size: 0.78rem; color: var(--text-secondary);
}
.restore-upload { margin-top: 12px; }
.msg-error { color: #ef4444; font-size: 0.85rem; }

/* Code editor */
.code-editor {
  width: 100%; padding: 14px; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 8px; color: var(--text-primary); font-family: monospace; font-size: 0.85rem;
  resize: vertical; line-height: 1.5; transition: border-color 0.15s;
}

/* Policies */
.policy-card { background: var(--bg-input); border-radius: 10px; padding: 16px; margin-top: 12px; }
.policy-header { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
.policy-ip { color: var(--text-primary); font-weight: 600; font-family: monospace; }
.policy-name { color: var(--text-muted); font-size: 0.85rem; flex: 1; }
.policy-row { margin-bottom: 10px; }

.cat-toggles { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 4px; }
.cat-check { display: flex; align-items: center; gap: 5px; cursor: pointer; }
.cat-check input { accent-color: #ef4444; }
.cat-check span { color: var(--text-secondary); font-size: 0.85rem; }

.inline-add { display: flex; gap: 6px; margin-top: 4px; }
.inline-add input {
  padding: 5px 10px; background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 6px; color: var(--text-primary); font-size: 0.85rem; flex: 1; max-width: 220px;
}
.btn-xs { padding: 5px 12px; color: #fff; border: none; border-radius: 6px; cursor: pointer; font-size: 0.8rem; transition: opacity 0.15s; }
.btn-xs.danger { background: #ef4444; }
.btn-xs.allow { background: #22c55e; }
.btn-xs:hover { opacity: 0.85; }

.tag-list { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.tag { display: flex; align-items: center; gap: 4px; padding: 3px 10px; border-radius: 6px; font-size: 0.8rem; }
.blocked-tag { background: rgba(239,68,68,0.1); color: #ef4444; }
.allow-tag { background: rgba(34,197,94,0.1); color: #22c55e; }
.tag button { background: none; border: none; color: inherit; cursor: pointer; font-size: 1rem; line-height: 1; }

/* Server settings */
.subsection { margin-bottom: 20px; }
.subsection h4 { color: var(--text-secondary); font-size: 0.95rem; margin-bottom: 10px; }
.settings-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 16px; }
.field { display: flex; flex-direction: column; gap: 6px; }
.field label { color: var(--text-muted); font-size: 0.85rem; font-weight: 500; }
.field input, .field select, .field textarea {
  padding: 10px 14px; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 8px; color: var(--text-primary); font-size: 0.92rem; transition: border-color 0.15s;
}
.field input:focus, .field select:focus, .field textarea:focus { border-color: var(--accent); outline: none; }
.field input::placeholder, .field textarea::placeholder { color: var(--text-dim); }
.checkbox-label { display: flex; align-items: center; gap: 8px; color: var(--text-secondary); font-size: 0.88rem; cursor: pointer; padding-top: 8px; }
.checkbox-label input { accent-color: var(--accent); }

/* Protocol grid */
.protocol-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 8px; }
.protocol-item {
  display: flex; align-items: center; gap: 12px; padding: 12px;
  background: var(--bg-input); border: 1px solid var(--border); border-radius: 10px; cursor: pointer;
  transition: border-color 0.15s;
}
.protocol-item:hover { border-color: var(--text-dim); }
.protocol-item input { accent-color: #22c55e; width: 18px; height: 18px; }
.protocol-info { display: flex; flex-direction: column; }
.protocol-name { color: var(--text-primary); font-weight: 500; font-size: 0.9rem; }
.protocol-port { color: var(--accent); font-size: 0.75rem; font-family: monospace; }
.protocol-desc { color: var(--text-dim); font-size: 0.75rem; }

/* Filtering mode */
.mode-cards { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.mode-card {
  padding: 20px; background: var(--bg-input); border: 2px solid var(--border); border-radius: 12px;
  cursor: pointer; transition: all 0.15s;
}
.mode-card:hover { border-color: var(--text-dim); }
.mode-card.active { border-color: var(--accent); background: var(--accent-glow); }
.mode-icon { font-size: 1.5rem; margin-bottom: 8px; }
.mode-info { display: flex; flex-direction: column; gap: 4px; }
.mode-title { color: var(--text-primary); font-weight: 600; font-size: 0.95rem; }
.mode-desc { color: var(--text-muted); font-size: 0.8rem; line-height: 1.4; }
.mode-cards.three-col { grid-template-columns: repeat(3, 1fr); }
.cluster-config { margin-top: 16px; }
.sync-options { display: flex; gap: 20px; flex-wrap: wrap; margin-top: 8px; }

/* Cluster status panel */
.cluster-status-panel {
  display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
  padding: 12px 16px; margin-bottom: 16px;
  background: var(--bg-input); border: 1px solid var(--border); border-radius: 10px;
}
.cluster-status-dot {
  width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0;
  background: #64748b;
}
.cluster-status-dot.online { background: #22c55e; box-shadow: 0 0 6px rgba(34,197,94,0.5); }
.cluster-status-dot.offline { background: #ef4444; box-shadow: 0 0 6px rgba(239,68,68,0.5); }
.cluster-status-dot.checking { background: #eab308; animation: pulse 1s infinite; }
@keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
.cluster-status-text { color: var(--text-secondary); font-size: 0.88rem; flex: 1; }
.cluster-status-text strong { color: var(--text-primary); }
.cluster-latency { color: var(--accent); font-size: 0.82rem; font-family: monospace; }
.btn-test-peer {
  padding: 5px 14px; background: var(--accent); color: #fff; border: none;
  border-radius: 6px; cursor: pointer; font-size: 0.8rem; white-space: nowrap;
  transition: opacity 0.15s;
}
.btn-test-peer:hover:not(:disabled) { opacity: 0.85; }
.btn-test-peer:disabled { opacity: 0.5; cursor: wait; }
.cluster-error { color: #ef4444; font-size: 0.78rem; }

/* Log management */
.log-stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; }
.info-item { display: flex; flex-direction: column; gap: 2px; padding: 10px 14px; background: var(--bg-input); border-radius: 8px; }
.info-label { color: var(--text-muted); font-size: 0.75rem; }
.info-value { color: var(--text-primary); font-size: 0.9rem; font-weight: 500; }
.btn-danger { padding: 9px 16px; background: rgba(239,68,68,0.15); color: #ef4444; border: 1px solid rgba(239,68,68,0.3); border-radius: 8px; cursor: pointer; font-size: 0.85rem; transition: background 0.15s; }
.btn-danger:hover { background: rgba(239,68,68,0.25); }
.btn-danger-outline { padding: 9px 16px; background: none; color: #ef4444; border: 1px solid rgba(239,68,68,0.3); border-radius: 8px; cursor: pointer; font-size: 0.85rem; transition: background 0.15s; }
.btn-danger-outline:hover { background: rgba(239,68,68,0.1); }

/* Users table */
.users-left table {
  width: 100%; border-collapse: separate; border-spacing: 0;
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px;
  overflow: hidden; margin-top: 8px;
}
.users-left table thead th {
  padding: 10px 14px; text-align: left; font-size: 0.75rem; font-weight: 600;
  color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em;
  background: var(--bg-input); border-bottom: 1px solid var(--border);
}
.users-left table tbody td {
  padding: 10px 14px; font-size: 0.85rem; color: var(--text-secondary);
  border-bottom: 1px solid var(--border); vertical-align: middle;
}
.users-left table tbody tr:last-child td { border-bottom: none; }
.users-left table tbody tr { transition: background 0.12s; }
.users-left table tbody tr:hover { background: var(--bg-input); }
.users-left table td.username { color: var(--text-primary); font-weight: 600; }
.users-left table td.actions { white-space: nowrap; }

/* Identity split + HIW panels */
.identity-split { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
.identity-left { }
.identity-right { }

.hiw-panel {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 20px;
}
.hiw-panel h4 { margin-bottom: 16px; color: var(--text); }
.hiw-steps { display: flex; flex-direction: column; gap: 14px; }
.hiw-step {
  display: flex;
  gap: 12px;
  align-items: flex-start;
}
.hiw-num {
  flex-shrink: 0;
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--accent);
  color: #fff;
  border-radius: 8px;
  font-size: 0.8rem;
  font-weight: 700;
}
.hiw-step strong { color: var(--text); font-size: 0.9rem; }
.hiw-step .section-desc { font-size: 0.8rem; margin-top: 2px; }
.hiw-tip {
  margin-top: 16px;
  padding: 12px;
  background: var(--bg-hover);
  border-radius: 8px;
  font-size: 0.8rem;
  color: var(--text-muted);
  line-height: 1.5;
}
.hiw-tip strong { color: var(--accent); }
.mgmt-https-apply {
  margin-top: 10px;
  padding: 12px;
  background: rgba(245, 158, 11, 0.08);
  border: 1px solid rgba(245, 158, 11, 0.25);
  border-radius: 8px;
}
.hiw-tip code { color: var(--accent); background: var(--bg); padding: 1px 4px; border-radius: 3px; }

/* Block Page Domain Setup — split layout */
.bp-domain-split {
  display: grid; grid-template-columns: 1fr 1fr; gap: 20px;
  margin-bottom: 20px; align-items: start;
}
.bp-domain-left, .bp-domain-right {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 18px;
}
.bp-domain-left h4, .bp-domain-right h4 {
  color: var(--text-secondary); font-size: 0.95rem; margin-bottom: 8px;
}
.bp-domain-row {
  display: flex; align-items: flex-end; gap: 0; margin-bottom: 8px;
}
.bp-domain-dot {
  color: var(--text-muted); font-size: 1.4rem; font-weight: 700;
  padding: 0 6px; margin-bottom: 8px; line-height: 40px;
}
.bp-domain-preview {
  display: flex; align-items: center; gap: 8px; padding: 8px 12px;
  background: var(--bg-input); border: 1px solid var(--border); border-radius: 8px;
}
.bp-preview-label { color: var(--text-muted); font-size: 0.8rem; }
.bp-preview-domain { color: var(--accent); font-size: 0.9rem; }
.bp-domain-status {
  display: flex; flex-direction: column; gap: 10px;
}
.bp-status-row {
  display: flex; align-items: center; gap: 8px; font-size: 0.85rem;
  padding: 8px 12px; background: var(--bg-input); border-radius: 8px;
}
.bp-status-label { color: var(--text-muted); min-width: 80px; font-weight: 500; }
.bp-status-row code { color: var(--accent); font-size: 0.82rem; word-break: break-all; }
.bp-cert-ok { color: #22c55e; font-weight: 600; }
.bp-cert-pending { color: #f59e0b; font-weight: 600; }
.bp-cert-none { color: var(--text-dim); }
.bp-status-empty { color: var(--text-dim); font-size: 0.85rem; padding: 20px 0; text-align: center; }
.btn-sm {
  padding: 2px 10px; font-size: 0.72rem; background: var(--accent); color: #fff;
  border: none; border-radius: 4px; cursor: pointer; margin-left: auto;
}
.msg-error { color: #ef4444; font-size: 0.82rem; }

@media (max-width: 768px) {
  .identity-split { grid-template-columns: 1fr; }
}
</style>

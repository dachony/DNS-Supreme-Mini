<template>
  <div class="query-log">
    <h2>Query Log</h2>

    <div class="filters">
      <input v-model="searchDomain" placeholder="Search domain..." @input="debouncedLoad" />
      <input v-model="searchClient" placeholder="Client IP..." @input="debouncedLoad" />
      <select v-model="filterBlocked" @change="loadLogs">
        <option value="">All</option>
        <option value="true">Blocked</option>
        <option value="false">Allowed</option>
      </select>
      <button @click="loadLogs" class="btn-refresh">Refresh</button>
    </div>

    <div class="log-table">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Client</th>
            <th>Domain</th>
            <th>Type</th>
            <th>Status</th>
            <th>Category</th>
            <th>Latency</th>
            <th>Upstream</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="log in logs" :key="log.id"
            :class="{ blocked: log.blocked }"
            @click="openDetail(log)"
            class="clickable-row">
            <td class="time">{{ formatTime(log.timestamp) }}</td>
            <td class="client-cell">
              <span>{{ formatClient(log.client_ip) }}</span>
              <span v-if="log.client_hostname" class="client-hostname">{{ log.client_hostname }}</span>
            </td>
            <td class="domain">{{ log.domain }}</td>
            <td>{{ log.query_type }}</td>
            <td>
              <span class="badge" :class="log.blocked ? 'badge-blocked' : 'badge-allowed'">
                {{ log.blocked ? 'BLOCKED' : 'ALLOWED' }}
              </span>
            </td>
            <td>
              <span v-if="log.blocked && parseCategory(log.block_rule)" class="badge-cat" :class="'cat-' + parseCategory(log.block_rule)">
                {{ formatCategory(log.block_rule) }}
              </span>
              <span v-else class="cat-none">-</span>
            </td>
            <td>{{ log.latency_ms?.toFixed(1) }}ms</td>
            <td class="upstream">{{ log.upstream || '-' }}</td>
          </tr>
          <tr v-if="!logs.length && !loading">
            <td colspan="8" class="empty">No queries logged yet</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="pagination" v-if="total > limit">
      <button :disabled="offset === 0" @click="prevPage">Previous</button>
      <span>{{ offset + 1 }}-{{ Math.min(offset + limit, total) }} of {{ total.toLocaleString() }}</span>
      <button :disabled="offset + limit >= total" @click="nextPage">Next</button>
    </div>

    <!-- Detail Popup -->
    <div v-if="selectedLog" class="modal-overlay" @click.self="selectedLog = null">
      <div class="modal-detail">
        <div class="modal-header">
          <h3>Query Detail</h3>
          <button @click="selectedLog = null" class="modal-close">&times;</button>
        </div>

        <div class="detail-status">
          <span class="badge large" :class="selectedLog.blocked ? 'badge-blocked' : 'badge-allowed'">
            {{ selectedLog.blocked ? 'BLOCKED' : 'ALLOWED' }}
          </span>
          <span v-if="selectedLog.blocked && parseCategory(selectedLog.block_rule)"
            class="badge-cat large" :class="'cat-' + parseCategory(selectedLog.block_rule)">
            {{ formatCategory(selectedLog.block_rule) }}
          </span>
        </div>

        <div class="detail-grid">
          <div class="detail-section">
            <h4>Request</h4>
            <div class="detail-row">
              <span class="detail-label">Domain</span>
              <span class="detail-value mono">{{ selectedLog.domain }}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Query Type</span>
              <span class="detail-value">{{ selectedLog.query_type }} ({{ queryTypeDesc(selectedLog.query_type) }})</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Timestamp</span>
              <span class="detail-value">{{ formatTimeFull(selectedLog.timestamp) }}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Protocol</span>
              <span class="detail-value">{{ formatProtocol(selectedLog.protocol) }}</span>
            </div>
          </div>

          <div class="detail-section">
            <h4>Source (Client)</h4>
            <div class="detail-row">
              <span class="detail-label">IP Address</span>
              <span class="detail-value mono">{{ parseIP(selectedLog.client_ip) }}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Port</span>
              <span class="detail-value mono">{{ parsePort(selectedLog.client_ip) }}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Hostname</span>
              <span class="detail-value">{{ selectedLog.client_hostname || 'Unknown (no reverse DNS)' }}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Device/User</span>
              <span class="detail-value">{{ selectedLog._deviceName || 'No device policy assigned' }}</span>
            </div>
          </div>

          <div class="detail-section">
            <h4>Response</h4>
            <div class="detail-row">
              <span class="detail-label">Response IP</span>
              <span class="detail-value mono">{{ selectedLog.response_ip || 'N/A (no answer)' }}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Upstream Server</span>
              <span class="detail-value mono">{{ formatUpstream(selectedLog.upstream) }}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Latency</span>
              <span class="detail-value">{{ selectedLog.latency_ms?.toFixed(2) }} ms</span>
            </div>
          </div>

          <div class="detail-section" v-if="selectedLog.blocked">
            <h4>Block Reason</h4>
            <div class="detail-row">
              <span class="detail-label">Category</span>
              <span class="detail-value">{{ formatCategory(selectedLog.block_rule) }}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Matched Rule</span>
              <span class="detail-value mono">{{ selectedLog.block_rule }}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Action Taken</span>
              <span class="detail-value">{{ selectedLog.response_ip ? 'Redirected to block page (' + selectedLog.response_ip + ')' : 'Returned NXDOMAIN (domain not found)' }}</span>
            </div>
          </div>

          <div class="detail-section" v-if="!selectedLog.blocked">
            <h4>Resolution</h4>
            <div class="detail-row">
              <span class="detail-label">Status</span>
              <span class="detail-value">Query allowed by filtering policy</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Resolved By</span>
              <span class="detail-value">{{ resolvedByDesc(selectedLog.upstream) }}</span>
            </div>
          </div>

          <div class="detail-section">
            <h4>Server</h4>
            <div class="detail-row">
              <span class="detail-label">DNS Server</span>
              <span class="detail-value">DNS Supreme</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Log ID</span>
              <span class="detail-value mono">#{{ selectedLog.id }}</span>
            </div>
          </div>
        </div>

        <div class="modal-actions">
          <button v-if="isAdmin && selectedLog.blocked" @click="addToAllowlist(selectedLog.domain)" class="btn-allow">
            Add to Allowlist
          </button>
          <button v-if="isAdmin && !selectedLog.blocked" @click="addToBlocklist(selectedLog.domain)" class="btn-block">
            Add to Blocklist
          </button>
          <button @click="filterByClient(selectedLog.client_ip)" class="btn-filter">
            Filter by this Client
          </button>
          <button @click="filterByDomain(selectedLog.domain)" class="btn-filter">
            Filter by this Domain
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import axios from 'axios'
import { currentUser } from '../auth'

const isAdmin = computed(() => currentUser.value?.role === 'admin')

const logs = ref<any[]>([])
const total = ref(0)
const loading = ref(false)
const limit = 50
const offset = ref(0)
const searchDomain = ref('')
const searchClient = ref('')
const filterBlocked = ref('')
const selectedLog = ref<any>(null)
let debounceTimer: any = null
let refreshInterval: any = null

function debouncedLoad() {
  clearTimeout(debounceTimer)
  debounceTimer = setTimeout(() => { offset.value = 0; loadLogs() }, 300)
}

async function loadLogs() {
  loading.value = true
  try {
    const params: any = { limit, offset: offset.value }
    if (searchDomain.value) params.domain = searchDomain.value
    if (searchClient.value) params.client_ip = searchClient.value
    if (filterBlocked.value) params.blocked = filterBlocked.value
    const { data } = await axios.get('/api/logs', { params })
    logs.value = data.data || []
    total.value = data.total || 0
  } catch (e) {
    // Log load failed silently — auto-refresh will retry
  } finally {
    loading.value = false
  }
}

function prevPage() { offset.value = Math.max(0, offset.value - limit); loadLogs() }
function nextPage() { offset.value += limit; loadLogs() }

async function openDetail(log: any) {
  const entry = { ...log, _deviceName: '' }
  // Try to find device policy for this client
  try {
    const ip = parseIP(log.client_ip)
    const { data } = await axios.get(`/api/policies/${ip}`)
    if (data?.name) {
      entry._deviceName = data.name
    } else if (data?.client_ip) {
      entry._deviceName = `Device policy: ${data.client_ip}`
    }
  } catch {
    // No policy for this IP
  }
  selectedLog.value = entry
}

// --- Formatting ---

function formatTime(ts: string) {
  return new Date(ts).toLocaleString([], {
    hour: '2-digit', minute: '2-digit', second: '2-digit', month: 'short', day: 'numeric'
  })
}

function formatTimeFull(ts: string) {
  return new Date(ts).toLocaleString([], {
    year: 'numeric', month: 'long', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    fractionalSecondDigits: 3,
  })
}

function formatClient(ip: string) {
  return ip?.replace(/:\d+$/, '') || ip
}

function parseIP(addr: string): string {
  if (!addr) return '-'
  const last = addr.lastIndexOf(':')
  if (last === -1) return addr
  return addr.substring(0, last)
}

function parsePort(addr: string): string {
  if (!addr) return '-'
  const last = addr.lastIndexOf(':')
  if (last === -1) return '-'
  return addr.substring(last + 1)
}

function formatProtocol(p: string): string {
  const labels: Record<string, string> = {
    'udp/tcp': 'DNS (UDP/TCP) — Standard, unencrypted',
    'dot': 'DNS-over-TLS (DoT) — Encrypted, port 853',
    'doh': 'DNS-over-HTTPS (DoH) — Encrypted, HTTPS',
    'doq': 'DNS-over-QUIC (DoQ) — Encrypted, QUIC',
  }
  return labels[p] || p || 'DNS (UDP/TCP)'
}

function formatUpstream(u: string): string {
  if (!u) return 'N/A'
  if (u === 'cache') return 'Local cache (no upstream query)'
  if (u === 'zone') return 'Local zone (authoritative)'
  const names: Record<string, string> = {
    '8.8.8.8:53': '8.8.8.8:53 (Google DNS)',
    '8.8.4.4:53': '8.8.4.4:53 (Google DNS)',
    '1.1.1.1:53': '1.1.1.1:53 (Cloudflare)',
    '1.0.0.1:53': '1.0.0.1:53 (Cloudflare)',
    '9.9.9.9:53': '9.9.9.9:53 (Quad9)',
  }
  return names[u] || u
}

function resolvedByDesc(upstream: string): string {
  if (!upstream) return 'Unknown'
  if (upstream === 'cache') return 'Served from DNS cache (previously resolved)'
  if (upstream === 'zone') return 'Answered from local authoritative zone'
  return 'Forwarded to upstream server ' + formatUpstream(upstream)
}

function queryTypeDesc(t: string): string {
  const descs: Record<string, string> = {
    A: 'IPv4 address', AAAA: 'IPv6 address', CNAME: 'Canonical name',
    MX: 'Mail exchange', TXT: 'Text record', NS: 'Nameserver',
    SOA: 'Start of authority', PTR: 'Pointer / reverse',
    SRV: 'Service locator', CAA: 'CA authorization',
  }
  return descs[t] || 'DNS record'
}

function parseCategory(rule: string): string {
  if (!rule) return ''
  // Network protection: [netprotect:geo], [netprotect:tor_exits], etc.
  const np = rule.match(/^\[netprotect:(\w+)\]/)
  if (np) return 'netprotect_' + np[1]
  // Standard blocklist: [ads], [malware], etc.
  const m = rule.match(/^\[(\w+)\]/)
  if (m) return m[1]
  if (rule.startsWith('custom:')) return 'custom'
  if (rule.includes('allowlist mode')) return 'allowlist'
  if (rule.startsWith('device-policy:')) return 'policy'
  return ''
}

function formatCategory(rule: string): string {
  const cat = parseCategory(rule)
  const labels: Record<string, string> = {
    ads: 'Ads', malware: 'Malware', adult: 'Adult', social: 'Social',
    gambling: 'Gambling', tracking: 'Tracking', custom: 'Custom Rule',
    allowlist: 'Not Allowed', policy: 'Device Policy', uncategorized: 'Other',
    netprotect_geo: 'Geo Block', netprotect_tor_exits: 'Tor Exit',
    netprotect_spamhaus_drop: 'Spamhaus', netprotect_botnet_c2: 'Botnet C2',
    netprotect_malicious_ips: 'Malicious IP', netprotect_abuse_ch: 'URLhaus',
  }
  return labels[cat] || cat || '-'
}

// --- Actions ---

async function addToAllowlist(domain: string) {
  const clean = domain.replace(/\.$/, '')
  await axios.post('/api/allowlist', { domain: clean })
  selectedLog.value = null
}

async function addToBlocklist(domain: string) {
  const clean = domain.replace(/\.$/, '')
  await axios.post('/api/custom-blocks', { domain: clean, reason: 'Added from query log' })
  selectedLog.value = null
}

function filterByClient(ip: string) {
  searchClient.value = parseIP(ip)
  selectedLog.value = null
  offset.value = 0
  loadLogs()
}

function filterByDomain(domain: string) {
  searchDomain.value = domain.replace(/\.$/, '')
  selectedLog.value = null
  offset.value = 0
  loadLogs()
}

onMounted(() => {
  loadLogs()
  refreshInterval = setInterval(loadLogs, 5000)
})

onUnmounted(() => {
  clearInterval(refreshInterval)
})
</script>

<style scoped>
.query-log h2 { margin-bottom: 20px; }

.filters { display: flex; gap: 12px; margin-bottom: 20px; }
.filters input, .filters select {
  padding: 8px 12px; background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 8px; color: var(--text-primary); font-size: 0.9rem;
}
.filters input { flex: 1; }
.filters input::placeholder { color: var(--text-dim); }
.btn-refresh {
  padding: 8px 20px; background: var(--accent); color: #fff; border: none;
  border-radius: 8px; cursor: pointer; font-size: 0.9rem; transition: background 0.15s;
}
.btn-refresh:hover { background: var(--accent-hover); }

.log-table { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
thead th {
  text-align: left; padding: 10px 8px; color: var(--text-muted); font-size: 0.8rem;
  text-transform: uppercase; border-bottom: 1px solid var(--border);
}
tbody tr { border-bottom: 1px solid var(--border); }
tbody tr.clickable-row { cursor: pointer; }
tbody tr:hover { background: var(--bg-hover); }
tbody tr.blocked { background: rgba(239,68,68,0.04); border-left: 2px solid rgba(239,68,68,0.4); }
td { padding: 8px; font-size: 0.85rem; }
.time { color: var(--text-muted); white-space: nowrap; }
.domain { color: var(--text-primary); word-break: break-all; max-width: 300px; }
.upstream { color: var(--text-muted); font-size: 0.8rem; }
.client-cell { display: flex; flex-direction: column; }
.client-hostname { color: var(--text-muted); font-size: 0.75rem; font-style: italic; }

.badge { padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
.badge.large { padding: 4px 12px; font-size: 0.85rem; }
.badge-allowed { background: rgba(34,197,94,0.15); color: #22c55e; }
.badge-blocked { background: rgba(239,68,68,0.15); color: #ef4444; }

.pagination {
  display: flex; align-items: center; justify-content: center; gap: 16px; margin-top: 20px;
}
.pagination button {
  padding: 6px 16px; background: var(--bg-card); border: 1px solid var(--border);
  color: var(--text-secondary); border-radius: 6px; cursor: pointer; transition: all 0.15s;
}
.pagination button:hover:not(:disabled) { border-color: var(--accent); color: var(--accent); }
.pagination button:disabled { opacity: 0.3; cursor: not-allowed; }
.pagination span { color: var(--text-muted); font-size: 0.85rem; }

.empty { text-align: center; padding: 40px; color: var(--text-dim); }

.badge-cat {
  padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 600;
  text-transform: uppercase; white-space: nowrap;
}
.badge-cat.large { padding: 4px 12px; font-size: 0.8rem; }
.cat-ads { background: rgba(239,68,68,0.12); color: #ef4444; }
.cat-malware { background: rgba(249,115,22,0.12); color: #f97316; }
.cat-adult { background: rgba(168,85,247,0.12); color: #a855f7; }
.cat-social { background: rgba(59,130,246,0.12); color: #3b82f6; }
.cat-gambling { background: rgba(234,179,8,0.12); color: #eab308; }
.cat-tracking { background: rgba(14,165,233,0.12); color: #0ea5e9; }
.cat-custom { background: rgba(100,116,139,0.12); color: #94a3b8; }
.cat-allowlist { background: rgba(239,68,68,0.12); color: #ef4444; }
.cat-policy { background: rgba(139,92,246,0.12); color: #8b5cf6; }
.cat-netprotect_geo { background: rgba(251,146,60,0.12); color: #fb923c; }
.cat-netprotect_tor_exits { background: rgba(220,38,38,0.12); color: #dc2626; }
.cat-netprotect_spamhaus_drop { background: rgba(220,38,38,0.12); color: #dc2626; }
.cat-netprotect_botnet_c2 { background: rgba(220,38,38,0.12); color: #dc2626; }
.cat-netprotect_malicious_ips { background: rgba(249,115,22,0.12); color: #f97316; }
.cat-netprotect_abuse_ch { background: rgba(249,115,22,0.12); color: #f97316; }
[class*="cat-netprotect_"] { border: 1px solid currentColor; border-opacity: 0.3; }
.cat-none { color: var(--text-dim); font-size: 0.8rem; }

/* Modal */
.modal-overlay {
  position: fixed; inset: 0; background: rgba(0,0,0,0.6); display: flex;
  align-items: center; justify-content: center; z-index: 100;
}
.modal-detail {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px;
  padding: 28px; width: 640px; max-width: 95vw; max-height: 90vh; overflow-y: auto;
  scrollbar-width: none; box-shadow: 0 16px 48px rgba(0,0,0,0.3);
}
.modal-detail::-webkit-scrollbar { display: none; }

.modal-header {
  display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;
}
.modal-header h3 { color: var(--text-primary); font-size: 1.1rem; }
.modal-close {
  background: none; border: none; color: var(--text-dim); font-size: 1.5rem;
  cursor: pointer; line-height: 1;
}
.modal-close:hover { color: var(--text-primary); }

.detail-status { display: flex; gap: 8px; margin-bottom: 20px; }

.detail-grid { display: flex; flex-direction: column; gap: 16px; }

.detail-section {
  background: var(--bg-input); border-radius: 10px; padding: 14px 16px;
}
.detail-section h4 {
  color: var(--text-muted); font-size: 0.78rem; text-transform: uppercase;
  letter-spacing: 0.5px; margin-bottom: 8px;
}

.detail-row { display: flex; align-items: flex-start; gap: 12px; padding: 4px 0; }
.detail-label { color: var(--text-muted); font-size: 0.82rem; min-width: 120px; flex-shrink: 0; }
.detail-value { color: var(--text-primary); font-size: 0.85rem; word-break: break-all; }
.detail-value.mono { font-family: monospace; }

.modal-actions {
  display: flex; gap: 8px; margin-top: 20px; flex-wrap: wrap;
  padding-top: 16px; border-top: 1px solid var(--border);
}
.btn-allow {
  padding: 8px 16px; background: rgba(34,197,94,0.15); color: #22c55e;
  border: 1px solid rgba(34,197,94,0.3); border-radius: 8px; cursor: pointer; font-size: 0.85rem;
  transition: background 0.15s;
}
.btn-allow:hover { background: rgba(34,197,94,0.25); }
.btn-block {
  padding: 8px 16px; background: rgba(239,68,68,0.15); color: #ef4444;
  border: 1px solid rgba(239,68,68,0.3); border-radius: 8px; cursor: pointer; font-size: 0.85rem;
  transition: background 0.15s;
}
.btn-block:hover { background: rgba(239,68,68,0.25); }
.btn-filter {
  padding: 8px 16px; background: var(--bg-input); color: var(--text-secondary);
  border: 1px solid var(--border); border-radius: 8px; cursor: pointer; font-size: 0.85rem;
  transition: all 0.15s;
}
.btn-filter:hover { border-color: var(--text-dim); color: var(--text-primary); }
</style>

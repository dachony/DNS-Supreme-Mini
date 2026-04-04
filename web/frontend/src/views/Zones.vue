<template>
  <div class="zones-page">
    <h2>DNS Zones</h2>

    <!-- Create Zone -->
    <div class="section" v-if="isAdmin && !selectedZone">
      <h3>Create New Zone</h3>
      <div class="zone-mode-toggle">
        <button type="button" :class="{ active: zoneMode === 'forward' }" @click="zoneMode = 'forward'">Forward Zone</button>
        <button type="button" :class="{ active: zoneMode === 'reverse' }" @click="zoneMode = 'reverse'">Reverse Zone (PTR)</button>
      </div>
      <p class="section-desc" v-if="zoneMode === 'forward'">Forward zones resolve domain names to IP addresses (A, AAAA, CNAME, MX, etc.)</p>
      <p class="section-desc" v-else>Reverse zones resolve IP addresses to hostnames (PTR records). Enter your subnet and the in-addr.arpa name will be generated automatically.</p>
      <form class="create-form" @submit.prevent="createZone">
        <div class="form-grid">
          <div class="field" v-if="zoneMode === 'forward'">
            <label>Zone Name</label>
            <input v-model="newZone.name" placeholder="example.com" required />
          </div>
          <div class="field" v-else>
            <label>Subnet</label>
            <div class="reverse-input-row">
              <input v-model="reverseSubnet" placeholder="192.168.1" @input="autoGenerateReverse" />
              <span class="reverse-preview" v-if="newZone.name">{{ newZone.name }}</span>
            </div>
          </div>
          <div class="field">
            <label>Zone Type</label>
            <select v-model="newZone.type">
              <option value="primary">Primary (authoritative)</option>
              <option value="secondary">Secondary (replica)</option>
            </select>
          </div>
          <div class="field">
            <label>Primary Nameserver</label>
            <select v-model="newZone.primary_ns" v-if="serverHostname">
              <option :value="serverHostname">{{ serverHostname }} (this server)</option>
              <option value="">Custom...</option>
            </select>
            <input v-if="!serverHostname || newZone.primary_ns === ''" v-model="newZone.primary_ns" placeholder="ns1.example.com" />
          </div>
          <div class="field">
            <label>Admin Email</label>
            <input v-model="newZone.admin_email" placeholder="admin.example.com" />
          </div>
          <div class="field">
            <label>Default TTL (seconds)</label>
            <input v-model.number="newZone.ttl" type="number" />
          </div>
        </div>
        <button type="submit" :disabled="!newZone.name" class="btn-primary">Create Zone</button>
      </form>
      <div v-if="error" class="msg-error">{{ error }}</div>
    </div>

    <!-- Zones List -->
    <div class="section" v-if="zones.length && !selectedZone">
      <div class="zones-header">
        <h3>Zones</h3>
        <div class="zone-filters">
          <button :class="{ active: zoneFilter === 'all' }" @click="zoneFilter = 'all'">All ({{ zones.length }})</button>
          <button :class="{ active: zoneFilter === 'forward' }" @click="zoneFilter = 'forward'">Forward ({{ forwardZoneCount }})</button>
          <button :class="{ active: zoneFilter === 'reverse' }" @click="zoneFilter = 'reverse'">Reverse ({{ reverseZoneCount }})</button>
        </div>
      </div>
      <div class="zones-list">
        <div v-for="z in filteredZones" :key="z.id" class="zone-row" @click="selectZone(z)">
          <div class="zone-row-badges">
            <span v-if="z.name === primaryDomain" class="zone-primary-badge">Primary</span>
            <span class="zone-type-badge" :class="z.type">{{ z.type }}</span>
            <span v-if="z.dnssec_signed" class="zone-dnssec-badge">DNSSEC</span>
            <span v-if="z.name.includes('arpa')" class="zone-reverse-badge">Reverse</span>
          </div>
          <div class="zone-row-info">
            <span class="zone-row-name">{{ z.name }}</span>
            <span class="zone-row-meta">{{ z.record_count }} records &middot; SOA {{ z.soa_serial }} &middot; TTL {{ z.ttl }}s</span>
          </div>
          <button @click.stop="exportZone(z)" class="zone-row-export-btn" title="Export zone file">Export</button>
          <button v-if="isAdmin && z.name !== primaryDomain" @click.stop="setAsPrimary(z)" class="zone-row-primary-btn" title="Set as primary domain">Set Primary</button>
          <button v-if="isAdmin" @click.stop="deleteZone(z)" class="zone-row-delete-btn">Delete</button>
        </div>
      </div>
    </div>

    <!-- Zone Detail -->
    <div v-if="selectedZone">
      <div class="zone-toolbar">
        <button @click="selectedZone = null; loadZones()" class="btn-back">Back to zones</button>
        <h3 class="zone-title">{{ selectedZone.name }}</h3>
        <span class="zone-type-badge" :class="selectedZone.type">{{ selectedZone.type }}</span>
        <span v-if="selectedZone.name.includes('arpa')" class="zone-reverse-badge">Reverse</span>
        <span v-if="zoneDNSSEC?.enabled" class="zone-dnssec-badge">DNSSEC</span>
      </div>

      <!-- Quick Info Bar -->
      <div class="zone-info-bar">
        <span>SOA Serial: <strong>{{ selectedZone.soa_serial }}</strong></span>
        <span>TTL: <strong>{{ selectedZone.ttl }}s</strong></span>
        <span>Type: <strong>{{ selectedZone.type === 'primary' ? 'Primary' : 'Secondary' }}</strong></span>
        <span>Records: <strong>{{ userRecords.length }}</strong></span>
        <div class="zone-info-actions" v-if="isAdmin && !selectedZone.name.includes('arpa')">
          <button @click="createSubdomainZone" class="btn-link">+ Subdomain Zone</button>
          <button v-if="!hasMatchingReverse" @click="createReverseForZone" class="btn-link">+ Reverse Zone</button>
          <span v-if="matchingReverseZone" class="zone-link" @click="selectZone(matchingReverseZone)">Reverse: {{ matchingReverseZone.name }}</span>
        </div>
      </div>

      <!-- SSL Certificate (collapsible) -->
      <div class="section section-cert" v-if="!selectedZone.name.includes('arpa')">
        <div class="cert-header" @click="showCertSection = !showCertSection">
          <h3>SSL Certificate</h3>
          <div class="cert-header-right">
            <span v-if="zoneCertInfo" class="cert-status-badge active">Active</span>
            <span v-else class="cert-status-badge none">No certificate</span>
            <span class="cert-collapse-icon">{{ showCertSection ? '\u25B2' : '\u25BC' }}</span>
          </div>
        </div>

        <div v-if="showCertSection" class="cert-body">
          <div v-if="zoneCertInfo" class="zone-cert-details">
            <div class="detail-row">
              <span class="detail-label">Subject</span>
              <span class="detail-value">{{ zoneCertInfo.subject }}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Issuer</span>
              <span class="detail-value">{{ zoneCertInfo.issuer }}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Expires</span>
              <span class="detail-value">{{ zoneCertInfo.not_after ? new Date(zoneCertInfo.not_after).toLocaleDateString() : '-' }}</span>
            </div>
            <div class="detail-row" v-if="zoneCertInfo.dns_names?.length">
              <span class="detail-label">DNS Names</span>
              <span class="detail-value">{{ zoneCertInfo.dns_names.join(', ') }}</span>
            </div>
          </div>

          <div v-if="isAdmin" class="zone-cert-actions">
            <button @click="generateZoneSelfSigned" class="btn-primary">Generate Self-Signed</button>
            <button @click="requestZoneAcmeCert" class="btn-primary" :disabled="!acmeConfigured || acmeRequesting">
              {{ acmeRequesting ? 'Requesting...' : 'Request Let\'s Encrypt' }}
            </button>
          </div>
          <div v-if="!acmeConfigured" class="hint-text" style="margin-top:6px">Configure ACME email in Settings &gt; Certificates to use Let's Encrypt.</div>
          <div v-if="zoneCertMsg" :class="zoneCertMsgType === 'error' ? 'msg-error' : 'msg-success'" style="margin-top:8px">{{ zoneCertMsg }}</div>
        </div>
      </div>

      <!-- DNS Records -->
      <div class="section">
        <h3>DNS Records</h3>
        <form v-if="isAdmin" class="record-form" @submit.prevent="addRecord">
          <div class="form-row">
            <div class="field rec-name-field">
              <label>Name</label>
              <input v-model="newRecord.name" placeholder="@ or subdomain" required />
            </div>
            <div class="field tiny">
              <label>Type</label>
              <select v-model="newRecord.type">
                <option v-for="t in recordTypes" :key="t" :value="t">{{ t }}</option>
              </select>
            </div>
            <div class="field rec-value-field">
              <label>Value</label>
              <input v-model="newRecord.value" :placeholder="valuePlaceholder" required />
            </div>
            <div class="field tiny">
              <label>TTL</label>
              <input v-model.number="newRecord.ttl" type="number" />
            </div>
            <div class="field tiny" v-if="['MX','SRV'].includes(newRecord.type)">
              <label>Priority</label>
              <input v-model.number="newRecord.priority" type="number" />
            </div>
            <label class="checkbox-inline" v-if="['A','AAAA'].includes(newRecord.type)">
              <input type="checkbox" v-model="createPTR" /> Create PTR
            </label>
            <button type="submit" class="btn-primary add-btn">Add Record</button>
          </div>
        </form>

        <table class="records-table">
          <thead>
            <tr><th>Name</th><th>Type</th><th>Value</th><th>TTL</th><th>Priority</th><th v-if="isAdmin"></th></tr>
          </thead>
          <tbody>
            <tr v-for="r in userRecords" :key="r.id">
              <template v-if="editingRecord?.id === r.id">
                <td><input v-model="editingRecord.name" class="inline-input" /></td>
                <td>
                  <select v-model="editingRecord.type" class="inline-select">
                    <option v-for="t in recordTypes" :key="t" :value="t">{{ t }}</option>
                  </select>
                </td>
                <td><input v-model="editingRecord.value" class="inline-input wide" /></td>
                <td><input v-model.number="editingRecord.ttl" type="number" class="inline-input narrow" /></td>
                <td><input v-model.number="editingRecord.priority" type="number" class="inline-input narrow" /></td>
                <td class="action-cell">
                  <button @click="saveEdit" class="btn-icon-save" title="Save">&#x2714;</button>
                  <button @click="editingRecord = null" class="btn-icon-cancel" title="Cancel">&#x2715;</button>
                </td>
              </template>
              <template v-else>
                <td class="rec-name">{{ r.name }}</td>
                <td><span class="rec-type-badge" :class="r.type.toLowerCase()">{{ r.type }}</span></td>
                <td class="rec-value">{{ r.value }}</td>
                <td>{{ r.ttl }}</td>
                <td>{{ r.priority || '' }}</td>
                <td v-if="isAdmin" class="action-cell">
                  <button @click="startEdit(r)" class="btn-rec-edit" title="Edit">Edit</button>
                  <button @click="deleteRecord(r)" class="btn-rec-delete" title="Delete">Delete</button>
                </td>
              </template>
            </tr>
            <tr v-if="!userRecords.length">
              <td colspan="6" class="empty-small">No records yet. Add one above.</td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Zone Infrastructure (SOA, NS, DNSSEC — bottom, collapsible) -->
      <div class="section section-infra">
        <div class="section-header-row">
          <h3>Zone Infrastructure</h3>
          <button @click="showInfra = !showInfra" class="btn-link">
            {{ showInfra ? 'Collapse' : 'Expand' }}
          </button>
        </div>

        <div v-if="showInfra">
          <!-- SOA / NS / DNSKEY / DS / CAA records -->
          <div class="system-records">
            <div v-for="group in systemRecordGroups" :key="group.type" class="sys-group">
              <div class="sys-group-header">
                <span class="rec-type-badge" :class="group.type.toLowerCase()">{{ group.type }}</span>
                <span class="sys-group-desc">{{ recordTypeDesc(group.type) }}</span>
              </div>
              <div v-for="r in group.records" :key="r.id" class="sys-record">
                <span class="sys-name" v-if="r.name !== '@'">{{ r.name }}</span>
                <span class="sys-value">{{ r.value }}</span>
                <span class="sys-ttl">TTL {{ r.ttl }}s</span>
              </div>
            </div>
          </div>

          <!-- DNSSEC -->
          <div class="dnssec-section">
            <h4>DNSSEC Signing</h4>
            <div v-if="zoneDNSSEC">
              <div class="dnssec-status">
                <div class="toggle-wrap" @click="isAdmin && toggleZoneDNSSEC()">
                  <div class="toggle" :class="{ on: zoneDNSSEC.enabled, disabled: !isAdmin }"><div class="toggle-knob"></div></div>
                  <span>{{ zoneDNSSEC.enabled ? 'Zone signing active' : 'Signing disabled' }}</span>
                </div>
              </div>
              <div class="dnssec-details">
                <div class="detail-row">
                  <span class="detail-label">Algorithm</span>
                  <span class="detail-value">{{ zoneDNSSEC.algorithm }}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Key Tag</span>
                  <span class="detail-value mono">{{ zoneDNSSEC.key_tag }}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">DS Record</span>
                  <span class="detail-value mono small">{{ zoneDNSSEC.ds_record }}</span>
                  <button @click="copyText(zoneDNSSEC.ds_record)" class="btn-copy">Copy</button>
                </div>
                <p class="section-desc">Add the DS record above to your domain registrar to complete DNSSEC chain of trust.</p>
              </div>
              <button v-if="isAdmin" @click="removeZoneDNSSEC" class="btn-text-danger">Remove DNSSEC key</button>
            </div>
            <div v-else>
              <p class="section-desc">This zone is not signed. Enable DNSSEC to protect against DNS spoofing.</p>
              <button v-if="isAdmin" @click="signZone" class="btn-primary">Enable DNSSEC Signing</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, inject, onMounted } from 'vue'
import axios from 'axios'
import { currentUser } from '../auth'

const confirm = inject('confirm') as (opts: any) => Promise<boolean>
const isAdmin = computed(() => currentUser.value?.role === 'admin')

const zones = ref<any[]>([])
const selectedZone = ref<any>(null)
const zoneFilter = ref('all')

const forwardZoneCount = computed(() => zones.value.filter(z => !z.name.includes('arpa')).length)
const reverseZoneCount = computed(() => zones.value.filter(z => z.name.includes('arpa')).length)
const filteredZones = computed(() => {
  if (zoneFilter.value === 'forward') return zones.value.filter(z => !z.name.includes('arpa'))
  if (zoneFilter.value === 'reverse') return zones.value.filter(z => z.name.includes('arpa'))
  return zones.value
})
const primaryDomain = ref('')
const serverHostname = ref('')

async function loadPrimaryDomain() {
  try {
    const { data } = await axios.get('/api/settings/primary-domain')
    primaryDomain.value = data.domain || ''
  } catch {}
}

async function loadServerHostname() {
  try {
    const { data } = await axios.get('/api/settings/hostname')
    serverHostname.value = data.hostname || ''
    // Pre-fill new zone nameserver
    if (serverHostname.value && !newZone.value.primary_ns) {
      newZone.value.primary_ns = serverHostname.value
    }
  } catch {}
}

async function setAsPrimary(z: any) {
  await axios.put('/api/settings/primary-domain', { domain: z.name })
  primaryDomain.value = z.name
}
const records = ref<any[]>([])
const zoneDNSSEC = ref<any>(null)
const showInfra = ref(false)
const error = ref('')
const zoneMode = ref('forward')
const reverseSubnet = ref('')

const recordTypes = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'PTR', 'CAA']

const newZone = ref({ name: '', type: 'primary', ttl: 3600, primary_ns: '', admin_email: '' })
const newRecord = ref({ name: '', type: 'A', value: '', ttl: 3600, priority: 0 })
const createPTR = ref(false)
const editingRecord = ref<any>(null)

const valuePlaceholder = computed(() => {
  const ph: Record<string, string> = {
    A: '192.168.1.1', AAAA: '2001:db8::1', CNAME: 'other.example.com',
    MX: 'mail.example.com', TXT: 'v=spf1 include:example.com ~all',
    NS: 'ns1.example.com', SRV: '0 5060 sip.example.com', PTR: 'host.example.com',
    CAA: '0 issue letsencrypt.org',
  }
  return ph[newRecord.value.type] || 'Value'
})

const systemTypes = ['SOA', 'NS', 'DNSKEY', 'DS', 'CAA']
const systemRecords = computed(() => records.value.filter(r => systemTypes.includes(r.type)))
const userRecords = computed(() => records.value.filter(r => !systemTypes.includes(r.type)))

const systemRecordGroups = computed(() => {
  const groups: Record<string, any[]> = {}
  for (const r of systemRecords.value) {
    if (!groups[r.type]) groups[r.type] = []
    groups[r.type].push(r)
  }
  return Object.entries(groups).map(([type, records]) => ({ type, records }))
})

function recordTypeDesc(type: string): string {
  const descs: Record<string, string> = {
    SOA: 'Start of Authority — defines the zone\'s primary nameserver, admin contact, and timing parameters',
    NS: 'Name Server — authoritative nameservers for this zone',
    DNSKEY: 'DNSSEC public key — used to verify signed records',
    DS: 'Delegation Signer — submit this to your registrar for DNSSEC chain of trust',
    CAA: 'Certificate Authority Authorization — which CAs can issue certificates for this domain',
  }
  return descs[type] || ''
}

async function loadZones() {
  const { data } = await axios.get('/api/zones')
  zones.value = data || []
}

async function createZone() {
  error.value = ''
  try {
    await axios.post('/api/zones', newZone.value)
    newZone.value = { name: '', type: 'primary', ttl: 3600, primary_ns: '', admin_email: '' }
    loadZones()
  } catch (e: any) {
    error.value = e.response?.data?.error || 'Failed to create zone'
  }
}

async function deleteZone(z: any) {
  if (!await confirm({ title: 'Delete Zone', message: `Delete zone "${z.name}" and all its records? This cannot be undone.`, confirmText: 'Delete', danger: true })) return
  await axios.delete(`/api/zones/${z.id}`)
  loadZones()
}

async function selectZone(z: any) {
  const { data } = await axios.get(`/api/zones/${z.id}`)
  selectedZone.value = data.zone
  records.value = data.records || []
  zoneDNSSEC.value = data.dnssec || null
  // Auto-select PTR for reverse zones
  if (data.zone?.name?.includes('arpa')) {
    newRecord.value.type = 'PTR'
  } else {
    newRecord.value.type = 'A'
    loadZoneCert(data.zone.name)
  }
}

async function addRecord() {
  await axios.post(`/api/zones/${selectedZone.value.id}/records`, newRecord.value)

  // Create PTR record in reverse zone if requested
  if (createPTR.value && ['A', 'AAAA'].includes(newRecord.value.type) && newRecord.value.value) {
    const ip = newRecord.value.value
    const hostname = (newRecord.value.name === '@' ? '' : newRecord.value.name + '.') + selectedZone.value.name
    try {
      await axios.post('/api/zones/ptr', { ip, hostname })
    } catch {
      // Reverse zone may not exist — that's OK
    }
  }

  createPTR.value = false
  newRecord.value = { name: '', type: 'A', value: '', ttl: 3600, priority: 0 }
  selectZone(selectedZone.value)
}

function startEdit(r: any) {
  editingRecord.value = { ...r }
}

async function saveEdit() {
  const r = editingRecord.value
  await axios.put(`/api/zones/${selectedZone.value.id}/records/${r.id}`, {
    name: r.name, type: r.type, value: r.value, ttl: r.ttl, priority: r.priority || 0,
  })
  editingRecord.value = null
  selectZone(selectedZone.value)
}

async function deleteRecord(r: any) {
  if (!await confirm({ title: 'Delete Record', message: `Delete ${r.type} record "${r.name}"?`, confirmText: 'Delete', danger: true })) return
  await axios.delete(`/api/zones/${selectedZone.value.id}/records/${r.id}`)
  selectZone(selectedZone.value)
}

async function signZone() {
  await axios.post('/api/dnssec/generate', { zone_name: selectedZone.value.name })
  selectZone(selectedZone.value)
}

async function toggleZoneDNSSEC() {
  await axios.put(`/api/dnssec/${selectedZone.value.name}`, { enabled: !zoneDNSSEC.value.enabled })
  selectZone(selectedZone.value)
}

async function removeZoneDNSSEC() {
  if (!await confirm({ title: 'Remove DNSSEC', message: 'Remove DNSSEC key? This will disable zone signing.', confirmText: 'Remove', danger: true })) return
  await axios.delete(`/api/dnssec/${selectedZone.value.name}`)
  selectZone(selectedZone.value)
}

function copyText(t: string) { navigator.clipboard.writeText(t) }

async function exportZone(z: any) {
  try {
    const { data } = await axios.get(`/api/zones/${z.id}/export`, { responseType: 'blob' })
    const url = URL.createObjectURL(data)
    const a = document.createElement('a')
    a.href = url; a.download = z.name + '.zone'; a.click()
    URL.revokeObjectURL(url)
  } catch {}
}

const matchingReverseZone = computed(() => {
  if (!selectedZone.value || selectedZone.value.name.includes('arpa')) return null
  return zones.value.find((z: any) => z.name.includes('arpa'))
})
const hasMatchingReverse = computed(() => !!matchingReverseZone.value)

async function createReverseForZone() {
  selectedZone.value = null
  zoneMode.value = 'reverse'
  reverseSubnet.value = ''
  newZone.value.name = ''
}

function createSubdomainZone() {
  const parent = selectedZone.value.name
  selectedZone.value = null
  zoneMode.value = 'forward'
  newZone.value.name = 'sub.' + parent
}

// --- Zone Certificate ---
const zoneCertInfo = ref<any>(null)
const zoneCertMsg = ref('')
const zoneCertMsgType = ref('success')
const acmeConfigured = ref(false)
const acmeRequesting = ref(false)
const showCertSection = ref(false)
const requestRestart = inject('requestRestart') as () => void

async function loadZoneCert(zoneName: string) {
  zoneCertInfo.value = null
  try {
    const { data } = await axios.get(`/api/certs/export?format=info&domain=${encodeURIComponent(zoneName)}`)
    if (data?.subject) {
      zoneCertInfo.value = data
    }
  } catch {}
  try {
    const { data } = await axios.get('/api/acme/config')
    acmeConfigured.value = !!(data?.email)
  } catch {}
}

async function generateZoneSelfSigned() {
  zoneCertMsg.value = ''
  zoneCertMsgType.value = 'success'
  try {
    const { data } = await axios.post('/api/certs/generate', { domain: selectedZone.value.name })
    zoneCertMsg.value = data.message || 'Self-signed certificate generated.'
    requestRestart()
    setTimeout(() => loadZoneCert(selectedZone.value.name), 1000)
    setTimeout(() => zoneCertMsg.value = '', 5000)
  } catch (e: any) {
    zoneCertMsg.value = e.response?.data?.error || e.message
    zoneCertMsgType.value = 'error'
  }
}

async function requestZoneAcmeCert() {
  const domain = selectedZone.value.name
  // Validate domain
  const invalidSuffixes = ['.local', '.internal', '.lan', '.home', '.test', '.localhost', '.invalid', '.example']
  if (invalidSuffixes.some(s => domain.endsWith(s)) || !domain.includes('.') || domain.split('.').pop().length < 2) {
    zoneCertMsg.value = `Let's Encrypt cannot issue certificates for "${domain}". Only publicly resolvable domains are supported (e.g. example.com, dns.mycompany.org).`
    zoneCertMsgType.value = 'error'
    return
  }

  zoneCertMsg.value = 'Requesting certificate from Let\'s Encrypt...'
  zoneCertMsgType.value = 'success'
  acmeRequesting.value = true
  try {
    await axios.post('/api/acme/request', { domain })
    zoneCertMsg.value = 'Certificate request submitted. Waiting for validation...'
    // Poll ACME status every 3 seconds for 90 seconds
    let attempts = 0
    const poll = setInterval(async () => {
      attempts++
      try {
        const { data: status } = await axios.get(`/api/acme/status/${encodeURIComponent(domain)}`)
        if (status.status === 'issued') {
          clearInterval(poll)
          acmeRequesting.value = false
          zoneCertMsg.value = 'Certificate issued by Let\'s Encrypt!'
          zoneCertMsgType.value = 'success'
          requestRestart()
          loadZoneCert(domain)
          setTimeout(() => zoneCertMsg.value = '', 8000)
          return
        }
        if (status.status === 'failed') {
          clearInterval(poll)
          acmeRequesting.value = false
          zoneCertMsg.value = status.error || 'Certificate request failed. Check that the domain resolves to this server from the internet.'
          zoneCertMsgType.value = 'error'
          return
        }
      } catch {}
      if (attempts >= 30) {
        clearInterval(poll)
        acmeRequesting.value = false
        zoneCertMsg.value = 'Request timed out. Check server logs for details.'
        zoneCertMsgType.value = 'error'
      }
    }, 3000)
  } catch (e: any) {
    zoneCertMsg.value = e.response?.data?.error || e.message
    zoneCertMsgType.value = 'error'
    acmeRequesting.value = false
  }
}

function autoGenerateReverse() {
  const parts = reverseSubnet.value.trim().split('.').filter(p => p !== '').reverse()
  if (parts.length > 0) {
    newZone.value.name = parts.join('.') + '.in-addr.arpa'
  } else {
    newZone.value.name = ''
  }
}

onMounted(() => { loadZones(); loadPrimaryDomain(); loadServerHostname() })
</script>

<style scoped>
.zones-page h2 { margin-bottom: 24px; }

/* Zone info bar */
.zone-info-bar {
  display: flex; gap: 20px; padding: 10px 16px; margin-bottom: 16px;
  background: var(--bg-input); border: 1px solid var(--border); border-radius: 8px;
  font-size: 0.85rem; color: var(--text-secondary); flex-wrap: wrap;
}
.zone-info-bar strong { color: var(--text-primary); }
.zone-link {
  color: var(--accent); cursor: pointer; font-size: 0.85rem; margin-left: auto;
  text-decoration: underline; text-underline-offset: 2px;
}
.zone-link:hover { opacity: 0.8; }
.zone-info-actions { display: flex; gap: 12px; align-items: center; margin-left: auto; }

/* Zone mode toggle */
.zone-mode-toggle {
  display: flex; gap: 0; margin-bottom: 12px; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; width: fit-content;
}
.zone-mode-toggle button {
  padding: 8px 20px; background: var(--bg-input); border: none; color: var(--text-secondary);
  cursor: pointer; font-size: 0.85rem; transition: all 0.15s;
}
.zone-mode-toggle button.active {
  background: var(--accent); color: #fff;
}

/* Reverse input */
.reverse-input-row { display: flex; gap: 10px; align-items: center; }
.reverse-input-row input { flex: 1; }
.reverse-preview {
  color: var(--accent); font-family: monospace; font-size: 0.82rem; white-space: nowrap;
}

/* Zone cert */
.section-cert { padding: 0 !important; overflow: hidden; }
.cert-header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 16px 24px; cursor: pointer; transition: background 0.15s;
}
.cert-header:hover { background: var(--bg-hover); }
.cert-header h3 { margin: 0; }
.cert-header-right { display: flex; align-items: center; gap: 10px; }
.cert-collapse-icon { color: var(--text-dim); font-size: 0.7rem; }
.cert-body { padding: 0 24px 20px; }
.zone-cert-details {
  background: var(--bg-input); border-radius: 8px; padding: 12px; margin-bottom: 12px;
}
.zone-cert-actions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.cert-status-badge {
  padding: 3px 10px; border-radius: 12px; font-size: 0.72rem; font-weight: 600; text-transform: uppercase;
}
.cert-status-badge.active { background: rgba(34,197,94,0.15); color: #22c55e; }
.cert-status-badge.none { background: rgba(100,116,139,0.15); color: #94a3b8; }
.hint-text { color: var(--text-dim); font-size: 0.78rem; font-style: italic; }
.msg-error { color: #ef4444; font-size: 0.85rem; }
.checkbox-inline {
  display: flex; align-items: center; gap: 5px; color: var(--text-secondary);
  font-size: 0.82rem; cursor: pointer; white-space: nowrap; align-self: flex-end; padding-bottom: 10px;
}
.checkbox-inline input { cursor: pointer; }

/* Infrastructure section */
.section-infra { opacity: 0.9; }
.dnssec-section { margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--border); }
.dnssec-section h4 { color: var(--text-primary); font-size: 0.95rem; margin-bottom: 10px; }

.section {
  background: var(--bg-card); border-radius: 12px; padding: 24px;
  border: 1px solid var(--border); margin-bottom: 16px;
}
.section h3 { color: var(--text-primary); font-size: 1rem; margin-bottom: 4px; }
.section h4 { color: var(--text-secondary); font-size: 0.9rem; margin: 12px 0 8px; }
.section-desc { color: var(--text-muted); font-size: 0.85rem; margin-bottom: 16px; line-height: 1.5; }
.section-header-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }

.btn-primary { padding: 9px 20px; background: linear-gradient(135deg, var(--accent), var(--brand-secondary, #818cf8)); color: #fff; border: none; border-radius: 8px; cursor: pointer; font-size: 0.9rem; transition: all 0.15s; }
.btn-primary:hover { opacity: 0.9; }
.btn-primary:disabled { opacity: 0.3; cursor: not-allowed; }
.btn-back { padding: 8px 16px; background: var(--bg-hover); border: none; color: var(--text-secondary); border-radius: 8px; cursor: pointer; font-size: 0.85rem; transition: all 0.15s; }
.btn-back:hover { color: var(--text-primary); }
.btn-link { background: none; border: none; color: var(--accent); cursor: pointer; font-size: 0.85rem; text-decoration: underline; }
.btn-text-danger { background: none; border: none; color: #ef4444; cursor: pointer; font-size: 0.85rem; padding: 4px 0; transition: opacity 0.15s; }
.btn-text-danger:hover { opacity: 0.8; }
.btn-copy { padding: 2px 8px; background: var(--bg-hover); color: var(--text-secondary); border: none; border-radius: 4px; cursor: pointer; font-size: 0.75rem; transition: all 0.15s; }
.btn-copy:hover { color: var(--text-primary); }
.action-cell { display: flex; gap: 6px; }
.btn-rec-edit {
  background: none; border: 1px solid var(--border); color: var(--text-secondary); cursor: pointer;
  font-size: 0.75rem; padding: 3px 10px; border-radius: 4px; transition: all 0.15s;
}
.btn-rec-edit:hover { border-color: var(--accent); color: var(--accent); }
.btn-rec-delete {
  background: none; border: 1px solid rgba(239,68,68,0.3); color: #ef4444; cursor: pointer;
  font-size: 0.75rem; padding: 3px 10px; border-radius: 4px; transition: all 0.15s;
}
.btn-rec-delete:hover { background: rgba(239,68,68,0.1); border-color: #ef4444; }
.btn-icon-save { background: none; border: none; color: #22c55e; cursor: pointer; font-size: 1rem; }
.btn-icon-cancel { background: none; border: none; color: #ef4444; cursor: pointer; font-size: 0.9rem; }

.inline-input {
  padding: 4px 8px; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 4px; color: var(--text-primary); font-size: 0.85rem; width: 100%;
  transition: border-color 0.15s;
}
.inline-input.wide { min-width: 180px; }
.inline-input.narrow { width: 70px; }
.inline-select {
  padding: 4px 6px; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 4px; color: var(--text-primary); font-size: 0.85rem;
}
.btn-xs { padding: 5px 12px; border: none; border-radius: 6px; cursor: pointer; font-size: 0.8rem; color: #fff; transition: opacity 0.15s; }
.btn-xs.primary { background: var(--accent); }
.btn-xs:hover { opacity: 0.85; }

.msg-error { background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3); color: #ef4444; padding: 8px 14px; border-radius: 8px; margin-top: 12px; font-size: 0.85rem; }
.empty-small { padding: 16px; text-align: center; color: var(--text-dim); font-size: 0.85rem; }

/* Create form */
.form-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; margin-bottom: 16px; }
.field { display: flex; flex-direction: column; gap: 4px; }
.field label { color: var(--text-muted); font-size: 0.8rem; }
.field input, .field select {
  padding: 9px 12px; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 8px; color: var(--text-primary); font-size: 0.9rem; transition: border-color 0.15s;
}
.field input::placeholder { color: var(--text-dim); }

.reverse-helper { margin-bottom: 12px; }
.reverse-input { display: flex; gap: 8px; margin-top: 6px; }
.reverse-input input { padding: 6px 10px; background: var(--bg-input); border: 1px solid var(--border); border-radius: 6px; color: var(--text-primary); font-size: 0.85rem; width: 180px; }

/* Zone toolbar */
.zone-toolbar { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
.zone-title { color: var(--text-primary); font-size: 1.2rem; }

/* Zones list */
.zones-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.zones-header h3 { margin: 0; }
.zone-filters { display: flex; gap: 0; border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }
.zone-filters button {
  padding: 5px 14px; background: var(--bg-input); border: none; color: var(--text-secondary);
  cursor: pointer; font-size: 0.8rem; transition: all 0.15s; border-right: 1px solid var(--border);
}
.zone-filters button:last-child { border-right: none; }
.zone-filters button.active { background: var(--accent); color: #fff; }
.zones-list { display: flex; flex-direction: column; gap: 6px; }
.zone-row {
  display: flex; align-items: center; gap: 14px; padding: 12px 16px;
  background: var(--bg-input); border: 1px solid var(--border); border-radius: 10px;
  cursor: pointer; transition: all 0.15s;
}
.zone-row:hover { border-color: var(--accent); background: var(--bg-hover); }
.zone-row-badges { display: flex; gap: 6px; flex-shrink: 0; }
.zone-type-badge { padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }
.zone-type-badge.primary { background: rgba(14,165,233,0.15); color: #0ea5e9; }
.zone-type-badge.secondary { background: rgba(168,85,247,0.15); color: #a855f7; }
.zone-dnssec-badge { padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; background: rgba(34,197,94,0.15); color: #22c55e; }
.zone-reverse-badge { padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; background: rgba(249,115,22,0.15); color: #f97316; }
.zone-row-info { flex: 1; min-width: 0; }
.zone-row-name { color: var(--text-primary); font-weight: 600; font-size: 0.95rem; display: block; }
.zone-row-meta { color: var(--text-muted); font-size: 0.78rem; display: block; margin-top: 2px; }
.zone-primary-badge { padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; background: linear-gradient(135deg, rgba(56,189,248,0.15), rgba(129,140,248,0.15)); color: #38bdf8; }
.zone-row-primary-btn {
  padding: 4px 10px; background: transparent; border: 1px solid rgba(56,189,248,0.3);
  color: #38bdf8; border-radius: 6px; cursor: pointer; font-size: 0.75rem;
  transition: all 0.15s; flex-shrink: 0;
}
.zone-row-primary-btn:hover { background: rgba(56,189,248,0.1); }
.zone-row-export-btn {
  padding: 4px 12px; background: transparent; border: 1px solid var(--border);
  color: var(--text-secondary); border-radius: 6px; cursor: pointer; font-size: 0.78rem;
  transition: all 0.15s; flex-shrink: 0;
}
.zone-row-export-btn:hover { border-color: var(--accent); color: var(--accent); }
.zone-row-delete-btn {
  padding: 4px 12px; background: transparent; border: 1px solid rgba(239,68,68,0.3);
  color: #ef4444; border-radius: 6px; cursor: pointer; font-size: 0.78rem;
  transition: all 0.15s; flex-shrink: 0;
}
.zone-row-delete-btn:hover { background: rgba(239,68,68,0.1); }

/* Zone info */
.zone-info-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 8px; }
.info-item { display: flex; flex-direction: column; gap: 2px; padding: 8px 12px; background: var(--bg-input); border-radius: 8px; }
.info-label { color: var(--text-muted); font-size: 0.75rem; }
.info-value { color: var(--text-primary); font-size: 0.9rem; }
.info-value.mono { font-family: monospace; }

.system-records { margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border); }
.sys-group { margin-bottom: 14px; }
.sys-group-header { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }
.sys-group-desc { color: var(--text-dim); font-size: 0.78rem; font-style: italic; }
.sys-record { display: flex; align-items: center; gap: 12px; padding: 6px 12px; background: var(--bg-input); border-radius: 6px; margin-bottom: 3px; font-size: 0.83rem; }
.sys-name { color: var(--accent); font-family: monospace; min-width: 60px; }
.sys-value { color: var(--text-secondary); flex: 1; word-break: break-all; font-family: monospace; font-size: 0.78rem; }
.sys-ttl { color: var(--text-dim); font-size: 0.75rem; white-space: nowrap; }
.rec-type-badge.soa { background: rgba(249,115,22,0.15); color: #f97316; }
.rec-type-badge.ns { background: rgba(168,85,247,0.15); color: #a855f7; }
.rec-type-badge.dnskey { background: rgba(34,197,94,0.15); color: #22c55e; }
.rec-type-badge.ds { background: rgba(234,179,8,0.15); color: #eab308; }
.rec-type-badge.caa { background: rgba(14,165,233,0.15); color: #0ea5e9; }

/* Records */
.record-form { margin-bottom: 16px; }
.form-row { display: flex; gap: 8px; align-items: flex-end; flex-wrap: wrap; }
.field.small { flex: 1; min-width: 120px; }
.rec-name-field { flex: 1; min-width: 80px; }
.rec-value-field { flex: 3; min-width: 200px; }
.field.tiny { flex: 0; min-width: 80px; }
.add-btn { align-self: flex-end; margin-bottom: 1px; }

.records-table { width: 100%; border-collapse: collapse; }
.records-table thead th { text-align: left; padding: 8px; color: var(--text-muted); font-size: 0.78rem; text-transform: uppercase; border-bottom: 1px solid var(--border); }
.records-table tbody tr { border-bottom: 1px solid var(--border); }
.records-table tbody tr:hover { background: var(--bg-hover); }
.records-table td { padding: 8px; font-size: 0.85rem; }
.rec-name { color: var(--text-primary); font-weight: 500; }
.rec-value { color: var(--text-secondary); word-break: break-all; max-width: 300px; }
.rec-type-badge { padding: 2px 6px; border-radius: 3px; font-size: 0.75rem; font-weight: 600; background: rgba(14,165,233,0.15); color: #0ea5e9; }
.rec-type-badge.system { background: rgba(100,116,139,0.15); color: var(--text-muted); }
.rec-type-badge.ptr { background: rgba(249,115,22,0.15); color: #f97316; }
.rec-type-badge.mx { background: rgba(168,85,247,0.15); color: #a855f7; }
.rec-type-badge.txt { background: rgba(234,179,8,0.15); color: #eab308; }
.rec-type-badge.cname { background: rgba(34,197,94,0.15); color: #22c55e; }

/* DNSSEC */
.dnssec-status { margin-bottom: 12px; }
.dnssec-details { background: var(--bg-input); border-radius: 8px; padding: 14px; margin-bottom: 8px; }
.detail-row { display: flex; align-items: flex-start; gap: 12px; padding: 4px 0; flex-wrap: wrap; }
.detail-label { color: var(--text-muted); font-size: 0.8rem; min-width: 90px; }
.detail-value { color: var(--text-primary); font-size: 0.85rem; flex: 1; }
.detail-value.mono { font-family: monospace; }
.detail-value.small { font-size: 0.75rem; color: var(--text-secondary); word-break: break-all; }

.toggle-wrap { display: flex; align-items: center; gap: 8px; cursor: pointer; }
.toggle { width: 36px; height: 20px; border-radius: 10px; background: var(--text-dim); position: relative; transition: background 0.2s; }
.toggle.on { background: #22c55e; }
.toggle-knob { width: 16px; height: 16px; border-radius: 50%; background: #fff; position: absolute; top: 2px; left: 2px; transition: transform 0.2s; }
.toggle.on .toggle-knob { transform: translateX(16px); }
</style>

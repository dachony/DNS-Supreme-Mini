<template>
  <div class="dashboard">
    <div class="dash-header">
      <h2>Dashboard</h2>
      <div class="toolbar">
        <div class="time-filter">
          <span class="toolbar-label">Period:</span>
          <button v-for="h in [1, 6, 24, 72, 168]" :key="h"
            :class="{ active: hours === h }" @click="loadStats(h)">
            {{ h < 24 ? h + 'h' : (h / 24) + 'd' }}
          </button>
        </div>
        <div class="refresh-filter">
          <span class="toolbar-label">Refresh:</span>
          <button v-for="r in refreshOptions" :key="r.value"
            :class="{ active: refreshInterval === r.value }" @click="setRefresh(r.value)">
            {{ r.label }}
          </button>
        </div>
      </div>
    </div>

    <!-- Stats bar across full width -->
    <div class="stats-grid" v-if="stats">
      <div class="stat-card total clickable" @click="goToLogs()">
        <div class="stat-icon">Q</div>
        <div class="stat-content">
          <div class="stat-value">{{ stats.total_queries?.toLocaleString() }}</div>
          <div class="stat-label">Total Queries</div>
        </div>
      </div>
      <div class="stat-card blocked clickable" @click="goToLogs({ blocked: 'true' })">
        <div class="stat-icon">B</div>
        <div class="stat-content">
          <div class="stat-value">{{ stats.blocked_queries?.toLocaleString() }}</div>
          <div class="stat-label">Blocked</div>
        </div>
      </div>
      <div class="stat-card allowed clickable" @click="goToLogs({ blocked: 'false' })">
        <div class="stat-icon">A</div>
        <div class="stat-content">
          <div class="stat-value">{{ stats.allowed_queries?.toLocaleString() }}</div>
          <div class="stat-label">Allowed</div>
        </div>
      </div>
      <div class="stat-card percent clickable" @click="goToBlocklists()">
        <div class="stat-icon">%</div>
        <div class="stat-content">
          <div class="stat-value">{{ stats.blocked_percent?.toFixed(1) }}%</div>
          <div class="stat-label">Block Rate</div>
        </div>
      </div>
    </div>

    <!-- Main 2/3 + 1/3 layout -->
    <div class="dash-body">

      <!-- LEFT 2/3: Traffic + Top Activity -->
      <div class="dash-left">

        <!-- Traffic -->
        <div class="panel">
          <div class="panel-header"><h3>Traffic</h3></div>
          <div class="traffic-inner">
            <div class="chart-area">
              <div class="chart-container">
                <Line v-if="chartData" :data="chartData" :options="chartOptions" />
                <div v-else class="chart-empty">No query data for this period</div>
              </div>
            </div>
            <div class="qt-area" v-if="stats?.query_types?.length">
              <h4>Query Types</h4>
              <div class="query-types-list">
                <div v-for="qt in stats.query_types" :key="qt.type" class="qt-row">
                  <span class="qt-type">{{ qt.type }}</span>
                  <div class="qt-bar-wrap">
                    <div class="qt-bar" :style="{ width: qtPercent(qt.count) + '%' }"></div>
                  </div>
                  <span class="qt-count">{{ qt.count.toLocaleString() }}</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Top Activity -->
        <div class="panel">
          <div class="panel-header"><h3>Top Activity</h3></div>
          <div class="tables-row">
            <div class="table-card top-domains">
              <h4>Top Domains</h4>
              <table>
                <tr v-for="(d, i) in stats?.top_domains" :key="d.domain" class="clickable-row" @click="goToLogs({ domain: d.domain })">
                  <td class="rank">{{ i + 1 }}</td>
                  <td class="domain">{{ d.domain }}</td>
                  <td class="count">{{ d.count.toLocaleString() }}</td>
                </tr>
                <tr v-if="!stats?.top_domains?.length"><td colspan="3" class="empty">No data</td></tr>
              </table>
            </div>
            <div class="table-card top-blocked">
              <h4>Top Blocked</h4>
              <table>
                <tr v-for="(d, i) in stats?.top_blocked" :key="d.domain" class="clickable-row" @click="goToLogs({ domain: d.domain, blocked: 'true' })">
                  <td class="rank">{{ i + 1 }}</td>
                  <td class="domain">{{ d.domain }}</td>
                  <td class="count">{{ d.count.toLocaleString() }}</td>
                </tr>
                <tr v-if="!stats?.top_blocked?.length"><td colspan="3" class="empty">No data</td></tr>
              </table>
            </div>
            <div class="table-card top-clients">
              <h4>Top Clients</h4>
              <table>
                <tr v-for="(c, i) in stats?.top_clients" :key="c.client_ip" class="clickable-row" @click="goToLogs({ client: c.client_ip })">
                  <td class="rank">{{ i + 1 }}</td>
                  <td class="domain">{{ c.client_ip }}</td>
                  <td class="count">{{ c.count.toLocaleString() }}</td>
                </tr>
                <tr v-if="!stats?.top_clients?.length"><td colspan="3" class="empty">No data</td></tr>
              </table>
            </div>
          </div>
        </div>
      </div>

      <!-- RIGHT 1/3: System Health + Protection -->
      <div class="dash-right">

        <!-- System Health -->
        <div class="panel" v-if="sysMetrics">
          <div class="panel-header">
            <h3>System Health</h3>
            <span class="badge-uptime" v-if="sysMetrics.uptime_seconds">{{ fmtUptime(sysMetrics.uptime_seconds) }}</span>
          </div>
          <div class="sys-stack">
            <div class="sys-item">
              <div class="sys-row"><span class="sys-label">CPU</span><span class="sys-val">{{ sysMetrics.cpu.usage_percent?.toFixed(0) }}%</span></div>
              <div class="sys-bar"><div class="sys-bar-fill" :style="{ width: sysMetrics.cpu.usage_percent + '%' }" :class="barColor(sysMetrics.cpu.usage_percent)"></div></div>
              <span class="sys-sub">{{ sysMetrics.cpu.num_cpu }} cores</span>
            </div>
            <div class="sys-item">
              <div class="sys-row"><span class="sys-label">Memory</span><span class="sys-val">{{ sysMetrics.memory.usage_percent?.toFixed(0) }}%</span></div>
              <div class="sys-bar"><div class="sys-bar-fill" :style="{ width: sysMetrics.memory.usage_percent + '%' }" :class="barColor(sysMetrics.memory.usage_percent)"></div></div>
              <span class="sys-sub">{{ fmtBytes(sysMetrics.memory.used_bytes) }} / {{ fmtBytes(sysMetrics.memory.total_bytes) }}</span>
            </div>
            <div class="sys-item" v-if="sysMetrics.app">
              <div class="sys-row"><span class="sys-label">App Memory</span><span class="sys-val">{{ fmtBytes(sysMetrics.app.heap_alloc) }}</span></div>
              <div class="sys-bar"><div class="sys-bar-fill" :style="{ width: appMemPercent + '%' }" :class="barColor(appMemPercent)"></div></div>
              <span class="sys-sub">{{ fmtBytes(sysMetrics.app.heap_alloc) }} / {{ fmtBytes(sysMetrics.app.heap_sys) }} heap &middot; {{ sysMetrics.app.goroutines }} goroutines</span>
            </div>
            <div class="sys-item">
              <div class="sys-row"><span class="sys-label">Disk</span><span class="sys-val">{{ sysMetrics.disk.usage_percent?.toFixed(0) }}%</span></div>
              <div class="sys-bar"><div class="sys-bar-fill" :style="{ width: sysMetrics.disk.usage_percent + '%' }" :class="barColor(sysMetrics.disk.usage_percent)"></div></div>
              <span class="sys-sub">{{ fmtBytes(sysMetrics.disk.used_bytes) }} / {{ fmtBytes(sysMetrics.disk.total_bytes) }}</span>
            </div>
            <div class="sys-item" v-if="sysMetrics.disk.app_size_bytes">
              <div class="sys-row"><span class="sys-label">App Disk</span><span class="sys-val">{{ fmtBytes(sysMetrics.disk.app_size_bytes) }}</span></div>
              <div class="sys-bar"><div class="sys-bar-fill" :style="{ width: appDiskPercent + '%' }" :class="barColor(appDiskPercent)"></div></div>
              <span class="sys-sub">{{ fmtBytes(sysMetrics.disk.app_size_bytes) }} / {{ fmtBytes(sysMetrics.disk.total_bytes) }}</span>
            </div>
            <div class="sys-item">
              <div class="sys-row"><span class="sys-label">Database</span><span class="sys-val">{{ sysMetrics.database.size_human }}</span></div>
              <span class="sys-sub">{{ sysMetrics.database.query_count?.toLocaleString() }} log entries</span>
            </div>
          </div>
        </div>

        <!-- Protection Status -->
        <div class="panel" v-if="serverStatus">
          <div class="panel-header"><h3>Protection</h3></div>
          <div class="prot-stack">
            <div class="prot-row clickable" @click="goToBlocklists()">
              <div class="prot-dot prot-lists"></div>
              <div class="prot-info">
                <span class="prot-name">Blocklists</span>
                <span class="prot-detail">{{ serverStatus.total_lists }} lists &middot; {{ serverStatus.total_domains?.toLocaleString() }} domains</span>
              </div>
            </div>
            <div class="prot-row clickable" v-if="sysMetrics?.app?.filter_domains" @click="goToBlocklists()">
              <div class="prot-dot prot-filter"></div>
              <div class="prot-info">
                <span class="prot-name">Filter Engine</span>
                <span class="prot-detail active">{{ sysMetrics.app.filter_domains?.toLocaleString() }} domains loaded{{ sysMetrics.app.blocked_services > 0 ? ' + ' + sysMetrics.app.blocked_services + ' services' : '' }}</span>
              </div>
            </div>
            <div class="prot-row clickable" @click="goToBlocklists()">
              <div class="prot-dot prot-np"></div>
              <div class="prot-info">
                <span class="prot-name">Network Protection</span>
                <span class="prot-detail" :class="serverStatus.np_active_feeds > 0 ? 'active' : ''">{{ serverStatus.np_active_feeds }} feeds active</span>
              </div>
            </div>
            <div class="prot-row clickable" @click="goToBlocklists()">
              <div class="prot-dot prot-geo"></div>
              <div class="prot-info">
                <span class="prot-name">Geo-Blocking</span>
                <span class="prot-detail" :class="serverStatus.geo_blocked_countries > 0 ? 'active' : ''">{{ serverStatus.geo_blocked_countries }} countries blocked</span>
              </div>
            </div>
            <div class="prot-row clickable" @click="goToSettings()">
              <div class="prot-dot prot-ban"></div>
              <div class="prot-info">
                <span class="prot-name">Fail2Ban</span>
                <span class="prot-detail" :class="serverStatus.banned_ips > 0 ? 'warn' : ''">{{ serverStatus.banned_ips }} banned IPs</span>
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>

    <div v-if="loading" class="loading">Loading dashboard...</div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed } from 'vue'
import { useRouter } from 'vue-router'
import axios from 'axios'
import { Line } from 'vue-chartjs'
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend, Filler } from 'chart.js'

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend, Filler)

const router = useRouter()
const stats = ref<any>(null)
const sysMetrics = ref<any>(null)
const appMemPercent = computed(() => {
  const app = sysMetrics.value?.app
  if (!app || !app.heap_sys) return 0
  return Math.min(100, Math.round((app.heap_alloc / app.heap_sys) * 100))
})
const appDiskPercent = computed(() => {
  const d = sysMetrics.value?.disk
  if (!d || !d.total_bytes) return 0
  return Math.min(100, Math.round((d.app_size_bytes / d.total_bytes) * 100))
})
const serverStatus = ref<any>(null)
const hours = ref(24)
const loading = ref(false)
const refreshInterval = ref(5)
let refreshTimer: any = null
let eventSource: EventSource | null = null
let sseRetryDelay = 5000

const refreshOptions = [
  { label: '1s', value: 1 },
  { label: '5s', value: 5 },
  { label: '10s', value: 10 },
  { label: '30s', value: 30 },
  { label: 'Off', value: 0 },
]

function setRefresh(seconds: number) {
  refreshInterval.value = seconds
  clearInterval(refreshTimer)
  if (seconds > 0) {
    refreshTimer = setInterval(() => loadStats(hours.value), seconds * 1000)
  }
}

function goToLogs(query?: Record<string, string>) { router.push({ path: '/logs', query }) }
function goToBlocklists() { router.push('/blocklists') }
function goToSettings() { router.push('/settings') }

const chartData = computed(() => {
  if (!stats.value?.queries_over_time?.length) return null
  const labels = stats.value.queries_over_time.map((t: any) =>
    new Date(t.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  )
  return {
    labels,
    datasets: [
      {
        label: 'Total',
        data: stats.value.queries_over_time.map((t: any) => t.total),
        borderColor: '#0ea5e9',
        backgroundColor: 'rgba(14,165,233,0.08)',
        fill: true, tension: 0.35, pointRadius: 2, borderWidth: 2,
      },
      {
        label: 'Blocked',
        data: stats.value.queries_over_time.map((t: any) => t.blocked),
        borderColor: '#ef4444',
        backgroundColor: 'rgba(239,68,68,0.08)',
        fill: true, tension: 0.35, pointRadius: 2, borderWidth: 2,
      }
    ]
  }
})

const chartOptions = computed(() => {
  const style = getComputedStyle(document.documentElement)
  const muted = style.getPropertyValue('--text-muted').trim() || '#64748b'
  const dim = style.getPropertyValue('--text-dim').trim() || '#475569'
  const border = style.getPropertyValue('--border').trim() || '#1e293b'
  return {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { intersect: false, mode: 'index' as const },
    plugins: { legend: { labels: { color: muted, usePointStyle: true, pointStyle: 'circle', padding: 16 } } },
    scales: {
      x: { ticks: { color: dim, maxRotation: 0 }, grid: { color: border } },
      y: { ticks: { color: dim }, grid: { color: border }, beginAtZero: true },
    }
  }
})

function qtPercent(count: number): number {
  if (!stats.value?.total_queries) return 0
  return Math.max(3, (count / stats.value.total_queries) * 100)
}

async function loadStats(h: number) {
  hours.value = h
  const isFirstLoad = !stats.value
  if (isFirstLoad) loading.value = true
  try {
    const [statsResp, metricsResp, statusResp] = await Promise.all([
      axios.get(`/api/stats?hours=${h}`),
      axios.get('/api/system-metrics'),
      axios.get('/api/status'),
    ])
    stats.value = statsResp.data
    sysMetrics.value = metricsResp.data
    serverStatus.value = statusResp.data
  } catch (e) {}
  finally { loading.value = false }
}

function fmtBytes(b: number): string {
  if (!b) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0; let v = b
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++ }
  return v.toFixed(i === 0 ? 0 : 1) + ' ' + units[i]
}

function fmtUptime(s: number): string {
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  if (d > 0) return `${d}d ${h}h ${m}m`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m`
}

function fmtNs(ns: number): string {
  if (!ns) return '0ms'
  if (ns < 1000) return ns + 'ns'
  if (ns < 1_000_000) return (ns / 1000).toFixed(1) + 'us'
  return (ns / 1_000_000).toFixed(2) + 'ms'
}

function barColor(pct: number): string {
  if (pct > 90) return 'bar-red'
  if (pct > 70) return 'bar-yellow'
  return 'bar-green'
}

function connectSSE() {
  const token = localStorage.getItem('token')
  if (!token) return
  if (eventSource) { eventSource.close(); eventSource = null }
  eventSource = new EventSource(`/api/events?token=${token}`)
  eventSource.addEventListener('stats', (event: MessageEvent) => {
    try {
      const newStats = JSON.parse(event.data)
      if (hours.value === 1) stats.value = newStats
    } catch (e) {}
  })
  eventSource.onerror = () => {
    if (eventSource) { eventSource.close(); eventSource = null }
    sseRetryDelay = Math.min(sseRetryDelay * 2, 60000)
    setTimeout(connectSSE, sseRetryDelay)
  }
  eventSource.onopen = () => { sseRetryDelay = 5000 }
}

onMounted(() => { loadStats(24); setRefresh(refreshInterval.value); connectSSE() })
onUnmounted(() => { clearInterval(refreshTimer); if (eventSource) { eventSource.close(); eventSource = null } })
</script>

<style scoped>
.dashboard h2 { margin: 0; font-size: 1.5rem; }

/* Header */
.dash-header {
  display: flex; justify-content: space-between; align-items: center;
  margin-bottom: 20px; flex-wrap: wrap; gap: 12px;
}
.toolbar { display: flex; gap: 16px; align-items: center; flex-wrap: wrap; }
.toolbar-label { font-size: 0.78rem; color: var(--text-muted); margin-right: 4px; }
.time-filter, .refresh-filter { display: flex; gap: 4px; align-items: center; }
.time-filter button, .refresh-filter button {
  padding: 4px 11px; border: 1px solid var(--border); background: var(--bg-card);
  color: var(--text-secondary); border-radius: 6px; cursor: pointer; font-size: 0.78rem; transition: all 0.15s;
}
.time-filter button:hover, .refresh-filter button:hover { border-color: var(--text-dim); }
.time-filter button.active { background: linear-gradient(135deg, #0ea5e9, #38bdf8); color: #fff; border-color: transparent; }
.refresh-filter button.active { background: linear-gradient(135deg, #7c3aed, #a78bfa); color: #fff; border-color: transparent; }

/* Stats bar */
.stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 18px; }
.stat-card {
  background: var(--bg-card); border-radius: 10px; padding: 14px 16px; border: 1px solid var(--border);
  display: flex; align-items: center; gap: 12px; border-left: 3px solid var(--border);
  transition: all 0.15s; cursor: pointer;
}
.stat-card:hover { transform: translateY(-1px); box-shadow: 0 3px 10px rgba(0,0,0,0.1); }
.stat-card:active { transform: scale(0.98); }
.stat-card.total { border-left-color: #38bdf8; }
.stat-card.blocked { border-left-color: #f87171; }
.stat-card.allowed { border-left-color: #34d399; }
.stat-card.percent { border-left-color: #fbbf24; }
.stat-icon {
  width: 36px; height: 36px; border-radius: 8px; display: flex;
  align-items: center; justify-content: center; font-size: 0.75rem; font-weight: 800; flex-shrink: 0;
}
.stat-card.total .stat-icon { background: rgba(56,189,248,0.12); color: #38bdf8; }
.stat-card.blocked .stat-icon { background: rgba(248,113,113,0.12); color: #f87171; }
.stat-card.allowed .stat-icon { background: rgba(52,211,153,0.12); color: #34d399; }
.stat-card.percent .stat-icon { background: rgba(251,191,36,0.12); color: #fbbf24; }
.stat-value { font-size: 1.4rem; font-weight: 700; color: var(--text-primary); line-height: 1.1; }
.stat-label { font-size: 0.72rem; color: var(--text-muted); margin-top: 1px; }
.stat-card.blocked .stat-value { color: #f87171; }
.stat-card.allowed .stat-value { color: #34d399; }
.stat-card.percent .stat-value { color: #fbbf24; }

/* Main body: 2/3 left + 1/3 right */
.dash-body { display: grid; grid-template-columns: 2fr 1fr; gap: 16px; align-items: start; }

/* Panels */
.panel {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px;
  padding: 18px; margin-bottom: 16px;
}
.panel:last-child { margin-bottom: 0; }
.panel-header {
  display: flex; align-items: center; justify-content: space-between;
  margin-bottom: 14px; padding-bottom: 10px; border-bottom: 1px solid var(--border);
}
.panel-header h3 { margin: 0; font-size: 0.92rem; color: var(--text-secondary); font-weight: 600; }

/* Traffic */
.traffic-inner { display: grid; grid-template-columns: 1fr 220px; gap: 16px; }
.chart-area { min-height: 0; }
.chart-container { height: 220px; }
.chart-empty { display: flex; align-items: center; justify-content: center; height: 100%; color: var(--text-dim); font-size: 0.82rem; }
.qt-area h4 { font-size: 0.8rem; color: var(--text-muted); margin-bottom: 10px; font-weight: 600; }
.query-types-list { display: flex; flex-direction: column; gap: 7px; }
.qt-row { display: flex; align-items: center; gap: 6px; }
.qt-type { width: 36px; font-size: 0.7rem; font-weight: 700; color: var(--text-muted); text-align: right; flex-shrink: 0; }
.qt-bar-wrap { flex: 1; height: 16px; background: rgba(100,116,139,0.08); border-radius: 4px; overflow: hidden; }
.qt-bar { height: 100%; border-radius: 4px; background: linear-gradient(90deg, #0ea5e9, #38bdf8); transition: width 0.4s; }
.qt-count { font-size: 0.7rem; color: var(--text-muted); min-width: 36px; text-align: right; font-variant-numeric: tabular-nums; }

/* Top Activity tables */
.tables-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
.table-card { border-left: 3px solid var(--border); padding-left: 12px; }
.table-card.top-domains { border-left-color: #38bdf8; }
.table-card.top-blocked { border-left-color: #f87171; }
.table-card.top-clients { border-left-color: #a78bfa; }
.table-card h4 { font-size: 0.8rem; font-weight: 600; margin-bottom: 8px; }
.table-card.top-domains h4 { color: #38bdf8; }
.table-card.top-blocked h4 { color: #f87171; }
.table-card.top-clients h4 { color: #a78bfa; }
table { width: 100%; }
tr { border-bottom: 1px solid var(--border); }
tr:last-child { border-bottom: none; }
td { padding: 5px 3px; font-size: 0.75rem; }
.rank { width: 18px; color: var(--text-dim); font-size: 0.65rem; text-align: center; }
.domain { color: var(--text-primary); word-break: break-all; }
.count { text-align: right; color: var(--text-muted); font-variant-numeric: tabular-nums; }
.empty { text-align: center; color: var(--text-dim); padding: 16px; }
.clickable-row { cursor: pointer; transition: background 0.1s; }
.clickable-row:hover { background: var(--bg-hover); }

/* System Health (right panel, stacked vertically) */
.badge-uptime {
  font-size: 0.68rem; padding: 2px 8px; border-radius: 12px;
  background: rgba(34,197,94,0.1); color: #22c55e; font-weight: 500;
}
.sys-stack { display: flex; flex-direction: column; gap: 12px; }
.sys-item { }
.sys-row { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 4px; }
.sys-label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.3px; }
.sys-val { font-size: 1rem; font-weight: 700; color: var(--text-primary); }
.sys-bar { height: 4px; background: rgba(100,116,139,0.1); border-radius: 2px; overflow: hidden; margin-bottom: 3px; }
.sys-bar-fill { height: 100%; border-radius: 2px; transition: width 0.5s; }
.sys-bar-fill.bar-green { background: linear-gradient(90deg, #22c55e, #4ade80); }
.sys-bar-fill.bar-yellow { background: linear-gradient(90deg, #eab308, #facc15); }
.sys-bar-fill.bar-red { background: linear-gradient(90deg, #ef4444, #f87171); }
.sys-sub { font-size: 0.68rem; color: var(--text-dim); }

/* Protection (right panel, stacked rows) */
.prot-stack { display: flex; flex-direction: column; gap: 10px; }
.prot-row {
  display: flex; align-items: center; gap: 10px; padding: 8px 10px;
  border-radius: 8px; transition: background 0.1s; cursor: pointer;
}
.prot-row:hover { background: var(--bg-hover); }
.prot-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.prot-dot.prot-lists { background: #38bdf8; }
.prot-dot.prot-np { background: #a855f7; }
.prot-dot.prot-geo { background: #22c55e; }
.prot-dot.prot-ban { background: #fbbf24; }
.prot-dot.prot-filter { background: #ec4899; }
.prot-info { display: flex; flex-direction: column; gap: 1px; }
.prot-name { font-size: 0.78rem; color: var(--text-primary); font-weight: 500; }
.prot-detail { font-size: 0.68rem; color: var(--text-muted); }
.prot-detail.active { color: #22c55e; }
.prot-detail.warn { color: #f59e0b; }

.clickable { cursor: pointer; }
.loading { text-align: center; padding: 60px; color: var(--text-muted); }

@media (max-width: 1100px) {
  .dash-body { grid-template-columns: 1fr; }
  .stats-grid { grid-template-columns: repeat(2, 1fr); }
  .traffic-inner { grid-template-columns: 1fr; }
  .tables-row { grid-template-columns: 1fr; }
}
</style>

<template>
  <div class="app" v-if="isAuthenticated">
    <nav class="sidebar">
      <div class="logo">
        <h1>DNS Supreme</h1>
        <span class="version">v2.0.0</span>
      </div>
      <ul class="nav-links">
        <li><router-link to="/" active-class="active" exact><span class="nav-icon nav-icon-dashboard"></span>Dashboard</router-link></li>
        <li><router-link to="/zones" active-class="active"><span class="nav-icon nav-icon-zones"></span>DNS Zones</router-link></li>
        <li><router-link to="/blocklists" active-class="active"><span class="nav-icon nav-icon-filter"></span>DNS Filtering</router-link></li>
        <li><router-link to="/logs" active-class="active"><span class="nav-icon nav-icon-logs"></span>Query Log</router-link></li>
        <li v-if="currentUser?.role === 'admin'"><router-link to="/settings" active-class="active"><span class="nav-icon nav-icon-settings"></span>Settings</router-link></li>
      </ul>
      <div class="sidebar-bottom">
        <div class="status" v-if="status">
          <div class="status-dot" :class="{ online: status.status === 'running' }"></div>
          <div class="status-text">
            <span class="status-label">{{ status.status === 'running' ? 'Active' : 'Offline' }}</span>
            <span class="status-count">{{ status.total_domains?.toLocaleString() }} blocked domains</span>
          </div>
        </div>
        <div class="sidebar-controls">
          <button @click="toggleTheme" class="btn-theme" :title="isDark ? 'Light' : 'Dark'">
            <span class="theme-icon">{{ isDark ? '\u2600' : '\u263E' }}</span>
            {{ isDark ? 'Light' : 'Dark' }}
          </button>
          <div class="zoom-controls">
            <button @click="zoomOut" class="btn-zoom" :disabled="zoomLevel <= 60" title="Zoom out">-</button>
            <span class="zoom-level">{{ zoomLevel }}%</span>
            <button @click="zoomIn" class="btn-zoom" :disabled="zoomLevel >= 140" title="Zoom in">+</button>
          </div>
        </div>
        <div class="user-info">
          <div class="user-details">
            <span class="user-name">{{ currentUser?.first_name || currentUser?.username }}</span>
            <span class="user-role">{{ currentUser?.role }}</span>
          </div>
          <button @click="handleLogout" class="btn-logout">Sign out</button>
        </div>
      </div>
    </nav>
    <main class="content">
      <div v-if="forcePasswordChange" class="force-pw-banner">
        <span>You are using the default admin password. Please change it immediately.</span>
        <router-link to="/users" class="force-pw-link">Change Password</router-link>
      </div>
      <router-view />

      <!-- Floating toast for TLS reload -->
      <Transition name="toast">
      <div v-if="needsRestart" class="restart-toast">
        <span>TLS reload required to apply new certificates.</span>
        <button @click="restartServer" :disabled="restarting" class="restart-toast-btn">
          {{ restarting ? 'Applying...' : 'Apply Now' }}
        </button>
        <button @click="needsRestart = false" class="restart-toast-dismiss">&times;</button>
      </div>
      </Transition>
    </main>
  </div>
  <router-view v-else />

  <!-- Global confirm modal -->
  <div v-if="confirmDialog.visible" class="confirm-overlay" @click.self="confirmDialog.resolve(false); confirmDialog.visible = false">
    <div class="confirm-modal">
      <h3>{{ confirmDialog.title }}</h3>
      <p>{{ confirmDialog.message }}</p>
      <div class="confirm-actions">
        <button @click="confirmDialog.resolve(false); confirmDialog.visible = false" class="confirm-btn cancel">Cancel</button>
        <button @click="confirmDialog.resolve(true); confirmDialog.visible = false" class="confirm-btn" :class="confirmDialog.danger ? 'danger' : 'primary'">
          {{ confirmDialog.confirmText || 'Confirm' }}
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, provide, onMounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import axios from 'axios'
import { isAuthenticated, currentUser, logout, forcePasswordChange } from './auth'

const router = useRouter()
const status = ref<any>(null)
const needsRestart = ref(false)
const restarting = ref(false)

async function restartServer() {
  restarting.value = true
  try {
    await axios.post('/api/restart')
    setTimeout(() => { restarting.value = false; needsRestart.value = false; loadStatus() }, 3000)
  } catch { restarting.value = false }
}

// Expose for child components
provide('requestRestart', () => { needsRestart.value = true })

// Global confirm dialog
const confirmDialog = reactive({
  visible: false,
  title: '',
  message: '',
  confirmText: 'Confirm',
  danger: false,
  resolve: (_v: boolean) => {},
})

function showConfirm(opts: { title: string; message: string; confirmText?: string; danger?: boolean }): Promise<boolean> {
  return new Promise((resolve) => {
    confirmDialog.title = opts.title
    confirmDialog.message = opts.message
    confirmDialog.confirmText = opts.confirmText || 'Confirm'
    confirmDialog.danger = opts.danger ?? true
    confirmDialog.resolve = (v: boolean) => { confirmDialog.visible = false; resolve(v) }
    confirmDialog.visible = true
  })
}

provide('confirm', showConfirm)
const isDark = ref(localStorage.getItem('theme') !== 'light')
const zoomLevel = ref(parseInt(localStorage.getItem('zoom') || '100'))

function zoomIn() {
  if (zoomLevel.value < 140) {
    zoomLevel.value += 5
    applyZoom()
  }
}
function zoomOut() {
  if (zoomLevel.value > 60) {
    zoomLevel.value -= 5
    applyZoom()
  }
}
function applyZoom() {
  document.documentElement.style.fontSize = (zoomLevel.value / 100 * 16) + 'px'
  localStorage.setItem('zoom', String(zoomLevel.value))
}
applyZoom()

function toggleTheme() {
  isDark.value = !isDark.value
  localStorage.setItem('theme', isDark.value ? 'dark' : 'light')
  applyTheme()
}

function applyTheme() {
  document.documentElement.setAttribute('data-theme', isDark.value ? 'dark' : 'light')
}

applyTheme()

async function loadStatus() {
  try {
    const { data } = await axios.get('/api/status')
    status.value = data
  } catch (e) {}
}

function handleLogout() {
  logout()
  router.push('/login')
}

watch(isAuthenticated, (val) => { if (val) loadStatus() })
onMounted(() => { if (isAuthenticated.value) loadStatus() })
</script>

<style>
:root, [data-theme="dark"] {
  --bg-body: #0c1222;
  --bg-sidebar: #111827;
  --bg-card: #1a2332;
  --bg-input: #0f172a;
  --bg-hover: #293548;
  --border: #1e3a5f;
  --text-primary: #e2e8f0;
  --text-secondary: #94a3b8;
  --text-muted: #64748b;
  --text-dim: #475569;
  --accent: #38bdf8;
  --accent-hover: #0ea5e9;
  --accent-glow: rgba(56, 189, 248, 0.15);
  --brand: #38bdf8;
  --brand-secondary: #818cf8;
  --nav-active-bg: linear-gradient(135deg, rgba(56, 189, 248, 0.15), rgba(129, 140, 248, 0.08));
  --sidebar-border: linear-gradient(to bottom, #1e3a5f 0%, rgba(56, 189, 248, 0.2) 50%, #1e3a5f 100%);
}

[data-theme="light"] {
  --bg-body: #f0f4f8;
  --bg-sidebar: #ffffff;
  --bg-card: #ffffff;
  --bg-input: #f5f8fb;
  --bg-hover: #e8edf4;
  --border: #d4dce8;
  --text-primary: #0f172a;
  --text-secondary: #475569;
  --text-muted: #64748b;
  --text-dim: #94a3b8;
  --accent: #0284c7;
  --accent-hover: #0369a1;
  --accent-glow: rgba(2, 132, 199, 0.1);
  --brand: #0284c7;
  --brand-secondary: #6366f1;
  --nav-active-bg: linear-gradient(135deg, rgba(2, 132, 199, 0.1), rgba(99, 102, 241, 0.05));
  --sidebar-border: linear-gradient(to bottom, #d4dce8 0%, rgba(2, 132, 199, 0.2) 50%, #d4dce8 100%);
}

* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: var(--bg-body); color: var(--text-primary);
  transition: background 0.2s, color 0.2s;
}

.app { display: flex; height: 100vh; overflow: hidden; }

.sidebar {
  width: 260px; min-width: 260px; height: 100vh;
  background: var(--bg-sidebar); padding: 24px 16px;
  display: flex; flex-direction: column;
  border-right: 1px solid transparent;
  border-image: var(--sidebar-border) 1;
  position: fixed; left: 0; top: 0; z-index: 10;
  transition: background 0.2s;
}

.logo {
  display: flex; align-items: baseline; gap: 6px;
  padding: 0 4px 20px; border-bottom: 1px solid var(--border);
}
.logo h1 {
  font-size: 1.3rem; font-weight: 700; letter-spacing: -0.5px;
  background: linear-gradient(135deg, var(--brand) 0%, var(--brand-secondary) 100%);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  background-clip: text;
}
.logo .version { font-size: 0.68rem; color: var(--text-dim); }

.nav-links { list-style: none; margin-top: 20px; flex: 1; }
.nav-links li { margin-bottom: 2px; }
.nav-links a {
  display: flex; align-items: center; gap: 10px;
  padding: 9px 14px; color: var(--text-secondary);
  text-decoration: none; border-radius: 8px; font-size: 0.88rem;
  transition: all 0.15s; position: relative;
}
.nav-links a:hover { background: var(--bg-hover); color: var(--text-primary); }
.nav-links a:hover .nav-icon { opacity: 1; }
.nav-links a.active {
  background: var(--nav-active-bg);
  color: var(--accent);
  border-left: 3px solid var(--accent);
  padding-left: 11px;
}
.nav-links a.active .nav-icon { opacity: 1; }

/* Nav icons as colored dots/indicators */
.nav-icon {
  width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0;
  opacity: 0.5; transition: opacity 0.15s;
}
.nav-icon-dashboard { background: #38bdf8; }
.nav-icon-zones { background: #a78bfa; }
.nav-icon-filter { background: #f87171; }
.nav-icon-logs { background: #34d399; }
.nav-icon-settings { background: #fbbf24; }
.nav-icon-users { background: #fb923c; }

.sidebar-bottom { display: flex; flex-direction: column; gap: 8px; }

.status {
  display: flex; align-items: center; gap: 10px;
  padding: 10px 12px; background: var(--bg-input); border-radius: 8px;
  border: 1px solid var(--border);
}
.status-dot {
  width: 8px; height: 8px; border-radius: 50%; background: #ef4444; flex-shrink: 0;
  box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.2);
}
.status-dot.online {
  background: #22c55e;
  box-shadow: 0 0 0 3px rgba(34, 197, 94, 0.2);
  animation: pulse-green 2s ease-in-out infinite;
}
@keyframes pulse-green {
  0%, 100% { box-shadow: 0 0 0 3px rgba(34, 197, 94, 0.2); }
  50% { box-shadow: 0 0 0 5px rgba(34, 197, 94, 0.1); }
}
.status-text { display: flex; flex-direction: column; }
.status-label { font-size: 0.75rem; font-weight: 600; color: var(--text-secondary); }
.status-count { font-size: 0.7rem; color: var(--text-muted); }

.sidebar-controls {
  display: flex; gap: 6px; align-items: center;
}
.btn-theme {
  padding: 6px 10px; background: var(--bg-input); border: 1px solid var(--border);
  color: var(--text-secondary); border-radius: 8px; cursor: pointer; font-size: 0.78rem;
  transition: all 0.15s; display: flex; align-items: center; gap: 4px; flex: 1;
}
.btn-theme:hover { border-color: var(--accent); color: var(--accent); }
.theme-icon { font-size: 0.9rem; }

.zoom-controls {
  display: flex; align-items: center; gap: 0;
  background: var(--bg-input); border: 1px solid var(--border); border-radius: 8px;
  overflow: hidden;
}
.btn-zoom {
  padding: 6px 10px; background: transparent; border: none;
  color: var(--text-secondary); cursor: pointer; font-size: 0.9rem; font-weight: 700;
  transition: all 0.15s;
}
.btn-zoom:hover { color: var(--accent); background: var(--bg-hover); }
.btn-zoom:disabled { opacity: 0.3; cursor: not-allowed; }
.zoom-level {
  padding: 0 4px; color: var(--text-muted); font-size: 0.7rem;
  min-width: 32px; text-align: center; font-variant-numeric: tabular-nums;
}

.user-info {
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 12px; background: var(--bg-input); border-radius: 8px;
  border: 1px solid var(--border);
}
.user-details { display: flex; flex-direction: column; }
.user-name { color: var(--text-primary); font-size: 0.85rem; font-weight: 500; }
.user-role {
  font-size: 0.68rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;
  color: var(--brand-secondary);
}

.btn-logout {
  padding: 4px 12px; background: transparent; border: 1px solid var(--border);
  color: var(--text-muted); border-radius: 6px; cursor: pointer; font-size: 0.78rem;
  transition: all 0.15s;
}
.btn-logout:hover { border-color: #ef4444; color: #ef4444; background: rgba(239,68,68,0.08); }

.content {
  flex: 1; margin-left: 260px; padding: 32px;
  height: 100vh; overflow-y: auto;
}
.content::-webkit-scrollbar { width: 6px; }
.content::-webkit-scrollbar-track { background: transparent; }
.content::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
.content::-webkit-scrollbar-thumb:hover { background: var(--text-dim); }
.content { scrollbar-width: thin; scrollbar-color: var(--border) transparent; }

/* Focus styles */
:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}

button:focus-visible, a:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}

input:focus, select:focus, textarea:focus {
  border-color: var(--accent) !important;
  outline: none;
}

/* Reduced motion */
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
}

/* Global theme overrides for child components */
.section, .stat-card, .chart-card, .table-card, .policy-card, .zone-card,
.dnssec-card, .list-item, .protocol-item, .mode-card, .forwarder-item,
.cert-info, .dnssec-details, .sys-record, .info-item, .system-records,
.zone-card, .login-card, .modal {
  background: var(--bg-card) !important;
  border-color: var(--border) !important;
  transition: background 0.2s, border-color 0.2s;
}

.forwarder-item, .sys-record, .info-item, .protocol-item, .cert-info,
.dnssec-details, .policy-card, .mode-card, .zone-card {
  background: var(--bg-input) !important;
}

.section h3, .zone-name, .rec-name, .list-name, .policy-ip, .user-name,
.forwarder-addr, .dnssec-zone, .mode-title, .protocol-name, .zone-title,
h2, h3 {
  color: var(--text-primary) !important;
}

.section-desc, .rec-value, .sys-value, .list-url, .zone-meta span,
.policy-name, .protocol-desc, .sys-group-desc, .mode-desc,
.detail-label, .info-label, .cert-label, .toggle-label, .forwarder-name,
p.section-desc {
  color: var(--text-muted) !important;
}

input, select, textarea, .code-editor, .inline-input, .inline-select {
  background: var(--bg-input) !important;
  border-color: var(--border) !important;
  color: var(--text-primary) !important;
  transition: background 0.2s, border-color 0.2s, color 0.2s;
}

input::placeholder, textarea::placeholder { color: var(--text-dim) !important; }

table thead th { color: var(--text-muted) !important; border-color: var(--border) !important; }
table tbody tr { border-color: var(--border) !important; }
table tbody tr:hover { background: var(--bg-hover) !important; }

.mode-card.active { border-color: var(--accent) !important; }

/* Restart banner */
.restart-toast {
  position: fixed; bottom: 24px; right: 24px; z-index: 200;
  display: flex; align-items: center; gap: 12px; padding: 14px 20px;
  background: #1e293b; border: 1px solid rgba(251,191,36,0.4); border-radius: 12px;
  color: #fbbf24; font-size: 0.88rem;
  box-shadow: 0 8px 32px rgba(0,0,0,0.4);
}
.restart-toast span { flex: 1; }
.restart-toast-btn {
  padding: 6px 16px; background: #f59e0b; color: #000; border: none;
  border-radius: 6px; cursor: pointer; font-size: 0.82rem; font-weight: 600;
  transition: opacity 0.15s; white-space: nowrap;
}
.restart-toast-btn:hover { opacity: 0.85; }
.restart-toast-btn:disabled { opacity: 0.5; cursor: wait; }
.restart-toast-dismiss {
  background: none; border: none; color: #fbbf24; cursor: pointer;
  font-size: 1.2rem; line-height: 1; opacity: 0.6;
}
.restart-toast-dismiss:hover { opacity: 1; }
.toast-enter-active { animation: toast-in 0.3s ease; }
.toast-leave-active { animation: toast-in 0.2s ease reverse; }
@keyframes toast-in { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }

/* Confirm modal */
.confirm-overlay {
  position: fixed; inset: 0; background: rgba(0,0,0,0.6); display: flex;
  align-items: center; justify-content: center; z-index: 200;
}
.confirm-modal {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 14px;
  padding: 24px; width: 400px; max-width: 90vw;
  box-shadow: 0 16px 48px rgba(0,0,0,0.3);
}
.confirm-modal h3 { color: var(--text-primary); font-size: 1.05rem; margin-bottom: 8px; }
.confirm-modal p { color: var(--text-secondary); font-size: 0.9rem; line-height: 1.5; margin-bottom: 20px; }
.confirm-actions { display: flex; gap: 8px; justify-content: flex-end; }
.confirm-btn {
  padding: 8px 20px; border: none; border-radius: 8px; cursor: pointer;
  font-size: 0.88rem; font-weight: 500; transition: all 0.15s;
}
.confirm-btn.cancel { background: var(--bg-hover); color: var(--text-secondary); }
.confirm-btn.cancel:hover { color: var(--text-primary); }
.confirm-btn.danger { background: #ef4444; color: #fff; }
.confirm-btn.danger:hover { background: #dc2626; }
.confirm-btn.primary { background: var(--accent); color: #fff; }
.confirm-btn.primary:hover { background: var(--accent-hover); }

.login-page { background: var(--bg-body) !important; }
.login-card { background: var(--bg-card) !important; border-color: var(--border) !important; }

.force-pw-banner {
  background: rgba(239, 68, 68, 0.15);
  border: 1px solid #ef4444;
  color: #ef4444;
  padding: 10px 16px;
  border-radius: 8px;
  margin-bottom: 16px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-size: 0.9rem;
}
.force-pw-link {
  color: #ef4444;
  font-weight: 600;
  text-decoration: underline;
}
</style>

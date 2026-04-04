<template>
  <div class="users-page">
    <h2>User Management</h2>

    <!-- Create User -->
    <div class="section">
      <h3>Create User</h3>
      <form class="user-form" @submit.prevent="createUser">
        <input v-model="form.username" placeholder="Username" required />
        <input v-model="form.password" type="password" placeholder="Password" required />
        <input v-model="form.first_name" placeholder="First Name" />
        <input v-model="form.last_name" placeholder="Last Name" />
        <input v-model="form.email" type="email" placeholder="Email" />
        <select v-model="form.role">
          <option value="viewer">Viewer</option>
          <option value="admin">Admin</option>
        </select>
        <button type="submit" class="btn-create">Create</button>
      </form>
      <div v-if="formError" class="error-msg">{{ formError }}</div>
      <div v-if="formSuccess" class="success-msg">{{ formSuccess }}</div>
    </div>

    <!-- Users List -->
    <div class="section">
      <h3>Users</h3>
      <table>
        <thead>
          <tr>
            <th>Username</th>
            <th>Name</th>
            <th>Email</th>
            <th>Role</th>
            <th>MFA</th>
            <th>Last Login</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="u in users" :key="u.id">
            <td class="username">{{ u.username }}</td>
            <td>{{ u.first_name }} {{ u.last_name }}</td>
            <td>{{ u.email || '-' }}</td>
            <td><span class="badge" :class="u.role">{{ u.role }}</span></td>
            <td>
              <span v-if="u.mfa_enabled" class="mfa-on">TOTP</span>
              <span v-else class="mfa-off">Off</span>
            </td>
            <td class="time">{{ u.last_login ? formatTime(u.last_login) : 'Never' }}</td>
            <td class="actions">
              <button @click="editUser(u)" class="btn-sm">Edit</button>
              <button @click="resetPw(u)" class="btn-sm warn">Reset PW</button>
              <button @click="deleteUser(u)" class="btn-sm danger"
                v-if="u.username !== currentUser?.username">Delete</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Edit Modal -->
    <div v-if="editing" class="modal-overlay" @click.self="editing = null">
      <div class="modal">
        <h3>Edit User: {{ editing.username }}</h3>
        <form @submit.prevent="saveEdit">
          <div class="field">
            <label>First Name</label>
            <input v-model="editing.first_name" />
          </div>
          <div class="field">
            <label>Last Name</label>
            <input v-model="editing.last_name" />
          </div>
          <div class="field">
            <label>Email</label>
            <input v-model="editing.email" type="email" />
          </div>
          <div class="field">
            <label>Role</label>
            <select v-model="editing.role">
              <option value="viewer">Viewer</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <div class="modal-actions">
            <button type="submit" class="btn-create">Save</button>
            <button type="button" @click="editing = null" class="btn-cancel">Cancel</button>
          </div>
        </form>
      </div>
    </div>

    <!-- MFA Section for current user -->
    <div class="section">
      <h3>My MFA Settings</h3>
      <div v-if="myUser?.mfa_enabled" class="mfa-status">
        <span class="mfa-on">MFA is enabled (TOTP)</span>
        <button @click="disableMFA" class="btn-sm danger">Disable MFA</button>
      </div>
      <div v-else>
        <button v-if="!mfaSetup" @click="setupMFA" class="btn-create">Setup TOTP</button>
        <div v-else class="mfa-setup">
          <p>Scan this code with your authenticator app or enter the secret manually:</p>
          <canvas ref="qrCanvas" style="margin:12px auto;display:block;border-radius:8px"></canvas>
          <div class="mfa-secret">{{ mfaSetup.secret }}</div>
          <form @submit.prevent="enableMFA" class="mfa-verify">
            <input v-model="mfaVerifyCode" placeholder="Enter 6-digit code" maxlength="6" />
            <button type="submit" class="btn-create">Enable MFA</button>
          </form>
          <div v-if="mfaError" class="error-msg">{{ mfaError }}</div>
        </div>
      </div>
    </div>

    <!-- Recovery Codes Modal -->
    <div v-if="recoveryCodes.length" class="modal-overlay" @click.self="recoveryCodes = []">
      <div class="modal-box" style="max-width:420px">
        <h3>Recovery Codes</h3>
        <p class="recovery-desc">Save these codes in a safe place. Each code can only be used once to sign in if you lose access to your authenticator app.</p>
        <div class="recovery-codes-grid">
          <code v-for="c in recoveryCodes" :key="c" class="recovery-code">{{ c }}</code>
        </div>
        <button @click="copyRecoveryCodes" class="btn-create" style="margin-top:16px;width:100%">Copy All Codes</button>
        <button @click="recoveryCodes = []" class="btn-cancel" style="margin-top:8px;width:100%">I've saved my codes</button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, inject, onMounted, nextTick } from 'vue'
import axios from 'axios'
import QRCode from 'qrcode'
import { currentUser } from '../auth'

const confirm = inject('confirm') as (opts: any) => Promise<boolean>

const users = ref<any[]>([])
const myUser = ref<any>(null)
const editing = ref<any>(null)
const mfaSetup = ref<any>(null)
const mfaVerifyCode = ref('')
const mfaError = ref('')
const qrCanvas = ref<HTMLCanvasElement | null>(null)
const recoveryCodes = ref<string[]>([])
const formError = ref('')
const formSuccess = ref('')

const form = ref({
  username: '', password: '', first_name: '', last_name: '', email: '', role: 'viewer'
})

async function loadUsers() {
  const { data } = await axios.get('/api/users')
  users.value = data
}

async function loadMe() {
  const { data } = await axios.get('/api/auth/me')
  myUser.value = data
}

async function createUser() {
  formError.value = ''; formSuccess.value = ''
  try {
    await axios.post('/api/users', form.value)
    formSuccess.value = `User '${form.value.username}' created`
    form.value = { username: '', password: '', first_name: '', last_name: '', email: '', role: 'viewer' }
    loadUsers()
  } catch (e: any) {
    formError.value = e.response?.data?.error || 'Failed to create user'
  }
}

function editUser(u: any) {
  editing.value = { ...u }
}

async function saveEdit() {
  await axios.put(`/api/users/${editing.value.id}`, editing.value)
  editing.value = null
  loadUsers()
}

async function resetPw(u: any) {
  // Redirects to Settings > Users tab
}

async function deleteUser(u: any) {
  if (!await confirm({ title: 'Delete User', message: `Delete user "${u.username}"? This cannot be undone.`, confirmText: 'Delete', danger: true })) return
  await axios.delete(`/api/users/${u.id}`)
  loadUsers()
}

async function setupMFA() {
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
}

async function enableMFA() {
  mfaError.value = ''
  try {
    const { data } = await axios.post('/api/auth/mfa/enable', { code: mfaVerifyCode.value })
    if (data.recovery_codes) {
      recoveryCodes.value = data.recovery_codes
    }
    mfaSetup.value = null
    mfaVerifyCode.value = ''
    loadMe()
  } catch (e: any) {
    mfaError.value = e.response?.data?.error || 'Invalid code'
  }
}

function copyRecoveryCodes() {
  navigator.clipboard.writeText(recoveryCodes.value.join('\n'))
}

async function disableMFA() {
  if (!await confirm({ title: 'Disable MFA', message: 'Disable multi-factor authentication? Your account will be less secure.', confirmText: 'Disable', danger: true })) return
  await axios.delete('/api/auth/mfa')
  loadMe()
}

function formatTime(ts: string) {
  return new Date(ts).toLocaleString([], {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
  })
}

onMounted(() => { loadUsers(); loadMe() })
</script>

<style scoped>
.users-page h2 { margin-bottom: 24px; }

.section {
  background: var(--bg-card); border-radius: 12px; padding: 20px;
  border: 1px solid var(--border); margin-bottom: 20px;
}
.section h3 { color: var(--text-secondary); font-size: 1rem; margin-bottom: 16px; }

.user-form {
  display: flex; gap: 8px; flex-wrap: wrap; align-items: flex-end;
}
.user-form input, .user-form select {
  padding: 8px 12px; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 6px; color: var(--text-primary); font-size: 0.9rem; flex: 1; min-width: 120px;
  transition: border-color 0.15s;
}
.user-form input::placeholder { color: var(--text-dim); }

.btn-create {
  padding: 8px 20px; background: linear-gradient(135deg, var(--accent), var(--brand-secondary, #818cf8)); color: #fff; border: none;
  border-radius: 6px; cursor: pointer; transition: all 0.15s;
}
.btn-create:hover { opacity: 0.9; }
.btn-cancel {
  padding: 8px 20px; background: transparent; color: var(--text-secondary);
  border: 1px solid var(--border); border-radius: 6px; cursor: pointer; transition: all 0.15s;
}
.btn-cancel:hover { border-color: var(--text-dim); color: var(--text-primary); }

table { width: 100%; border-collapse: collapse; }
thead th {
  text-align: left; padding: 8px; color: var(--text-muted); font-size: 0.8rem;
  text-transform: uppercase; border-bottom: 1px solid var(--border);
}
tbody tr { border-bottom: 1px solid var(--border); }
tbody tr:hover { background: var(--bg-hover); }
td { padding: 10px 8px; font-size: 0.9rem; }
.username { font-weight: 600; color: var(--text-primary); }
.time { color: var(--text-muted); font-size: 0.8rem; white-space: nowrap; }
.actions { display: flex; gap: 6px; }

.btn-sm {
  padding: 4px 10px; background: var(--bg-hover); border: none; color: var(--text-secondary);
  border-radius: 4px; cursor: pointer; font-size: 0.8rem; transition: all 0.15s;
}
.btn-sm:hover { color: var(--text-primary); }
.btn-sm.warn { color: #f59e0b; }
.btn-sm.warn:hover { background: rgba(245,158,11,0.15); }
.btn-sm.danger { color: #ef4444; }
.btn-sm.danger:hover { background: rgba(239,68,68,0.15); }

.badge { padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
.badge.admin { background: rgba(139,92,246,0.15); color: #8b5cf6; }
.badge.viewer { background: rgba(34,197,94,0.15); color: #22c55e; }

.mfa-on { color: #22c55e; font-weight: 600; font-size: 0.85rem; }
.mfa-off { color: var(--text-muted); font-size: 0.85rem; }

.mfa-status { display: flex; align-items: center; gap: 16px; }
.mfa-setup p { color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 8px; }
.mfa-secret {
  font-family: monospace; font-size: 1.1rem; color: #f59e0b; background: var(--bg-input);
  padding: 12px; border-radius: 8px; margin-bottom: 8px; word-break: break-all;
}
.mfa-uri { font-size: 0.75rem; color: var(--text-dim); word-break: break-all; margin-bottom: 12px; }
.mfa-verify { display: flex; gap: 8px; }
.mfa-verify input {
  padding: 8px 12px; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 6px; color: var(--text-primary); font-size: 1rem; width: 160px;
  transition: border-color 0.15s;
}

.error-msg {
  background: rgba(239,68,68,0.1); border: 1px solid #ef4444; color: #ef4444;
  padding: 8px 12px; border-radius: 6px; margin-top: 8px; font-size: 0.85rem;
}
.success-msg {
  background: rgba(34,197,94,0.1); border: 1px solid #22c55e; color: #22c55e;
  padding: 8px 12px; border-radius: 6px; margin-top: 8px; font-size: 0.85rem;
}

.recovery-desc { color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 12px; }
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
.modal-box {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px;
  padding: 24px; width: 420px; max-width: 90vw;
  box-shadow: 0 16px 48px rgba(0,0,0,0.3);
}
.modal-box h3 { color: var(--text-primary); margin-bottom: 16px; }

.modal-overlay {
  position: fixed; inset: 0; background: rgba(0,0,0,0.6); display: flex;
  align-items: center; justify-content: center; z-index: 100;
}
.modal {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px;
  padding: 24px; width: 420px; max-width: 90vw;
  box-shadow: 0 16px 48px rgba(0,0,0,0.3);
}
.modal h3 { color: var(--text-primary); margin-bottom: 16px; }
.field { margin-bottom: 12px; }
.field label { display: block; color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 4px; }
.field input, .field select {
  width: 100%; padding: 8px 12px; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 6px; color: var(--text-primary); transition: border-color 0.15s;
}
.modal-actions { display: flex; gap: 8px; margin-top: 16px; }
</style>

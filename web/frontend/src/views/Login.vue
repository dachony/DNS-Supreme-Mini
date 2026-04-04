<template>
  <div class="login-page">
    <div class="login-card">
      <h1>DNS Supreme</h1>
      <p class="subtitle">Sign in to your account</p>

      <div v-if="error" class="error-msg">{{ error }}</div>

      <!-- Login Form -->
      <form v-if="!mfaStep" @submit.prevent="handleLogin">
        <div class="field">
          <label>Username</label>
          <input v-model="username" type="text" placeholder="admin" autofocus />
        </div>
        <div class="field">
          <label>Password</label>
          <input v-model="password" type="password" placeholder="Password" />
        </div>
        <button type="submit" :disabled="loading" class="btn-login">
          {{ loading ? 'Signing in...' : 'Sign In' }}
        </button>
        <router-link to="/reset-password" class="forgot-link">Forgot password?</router-link>
      </form>

      <!-- MFA Form -->
      <form v-else @submit.prevent="handleMFA">
        <p class="mfa-info">Enter the 6-digit code from your authenticator app</p>
        <div class="field">
          <label>MFA Code</label>
          <input v-model="mfaCode" type="text" placeholder="000000" maxlength="6"
            autofocus autocomplete="one-time-code" />
        </div>
        <button type="submit" :disabled="loading" class="btn-login">
          {{ loading ? 'Verifying...' : 'Verify' }}
        </button>
        <button type="button" @click="mfaStep = false; error = ''" class="btn-back">Back to login</button>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { login, verifyMFA } from '../auth'

const router = useRouter()
const username = ref('')
const password = ref('')
const mfaCode = ref('')
const mfaStep = ref(false)
const loading = ref(false)
const error = ref('')

async function handleLogin() {
  error.value = ''
  loading.value = true
  try {
    const result = await login(username.value, password.value)
    if (result.mfaRequired) {
      mfaStep.value = true
    } else {
      router.push('/')
    }
  } catch (e: any) {
    error.value = e.response?.data?.error || 'Login failed'
    password.value = ''
  } finally {
    loading.value = false
  }
}

async function handleMFA() {
  error.value = ''
  loading.value = true
  try {
    await verifyMFA(mfaCode.value)
    router.push('/')
  } catch (e: any) {
    error.value = e.response?.data?.error || 'Invalid code'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page {
  min-height: 100vh; display: flex; align-items: center; justify-content: center;
  background: var(--bg-body);
  position: relative;
}
.login-page::before {
  content: ''; position: absolute; inset: 0; pointer-events: none;
  background:
    radial-gradient(ellipse at 20% 50%, rgba(56, 189, 248, 0.08) 0%, transparent 50%),
    radial-gradient(ellipse at 80% 20%, rgba(129, 140, 248, 0.06) 0%, transparent 50%),
    radial-gradient(ellipse at 60% 80%, rgba(52, 211, 153, 0.04) 0%, transparent 50%);
}
.login-card {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px;
  padding: 40px; width: 400px; max-width: 90vw; position: relative; z-index: 1;
  box-shadow: 0 8px 32px rgba(0,0,0,0.2);
}
.login-card h1 {
  font-size: 1.8rem; margin-bottom: 4px;
  background: linear-gradient(135deg, var(--brand), var(--brand-secondary, #818cf8));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  background-clip: text;
}
.subtitle { color: var(--text-muted); font-size: 0.9rem; margin-bottom: 24px; }

.field { margin-bottom: 16px; }
.field label { display: block; color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 6px; }
.field input {
  width: 100%; padding: 10px 14px; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 8px; color: var(--text-primary); font-size: 1rem; transition: border-color 0.15s;
}
.field input::placeholder { color: var(--text-dim); }

.btn-login {
  width: 100%; padding: 12px; background: linear-gradient(135deg, var(--accent), var(--brand-secondary, #818cf8)); color: #fff; border: none;
  border-radius: 8px; font-size: 1rem; cursor: pointer; margin-top: 8px; transition: all 0.2s; font-weight: 500;
}
.btn-login:hover { opacity: 0.9; transform: translateY(-1px); box-shadow: 0 4px 12px rgba(56,189,248,0.3); }
.btn-login:disabled { opacity: 0.5; cursor: not-allowed; }

.btn-back {
  width: 100%; padding: 10px; background: transparent; color: var(--text-muted);
  border: 1px solid var(--border); border-radius: 8px; cursor: pointer; margin-top: 8px;
  transition: border-color 0.15s, color 0.15s;
}
.btn-back:hover { border-color: var(--text-secondary); color: var(--text-secondary); }

.error-msg {
  background: rgba(239,68,68,0.1); border: 1px solid #ef4444; color: #ef4444;
  padding: 10px 14px; border-radius: 8px; margin-bottom: 16px; font-size: 0.9rem;
}

.mfa-info { color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 16px; }

.forgot-link {
  display: block;
  text-align: center;
  margin-top: 12px;
  color: var(--text-muted);
  font-size: 0.85rem;
  text-decoration: none;
  transition: color 0.15s;
}
.forgot-link:hover { color: var(--accent); }
</style>

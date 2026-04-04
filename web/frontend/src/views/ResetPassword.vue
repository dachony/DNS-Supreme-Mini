<template>
  <div class="login-page">
    <div class="login-card">
      <h1>DNS Supreme</h1>

      <!-- Success state -->
      <div v-if="success">
        <p class="subtitle" style="color:#10b981">{{ success }}</p>
        <router-link to="/login" class="btn-login" style="display:block;text-align:center;text-decoration:none;margin-top:16px">Back to Login</router-link>
      </div>

      <!-- Reset form (with token) -->
      <div v-else-if="token">
        <p class="subtitle">Enter your new password</p>
        <div v-if="error" class="error-msg">{{ error }}</div>
        <form @submit.prevent="handleReset">
          <div class="field">
            <label>New Password</label>
            <input v-model="newPassword" type="password" placeholder="At least 6 characters" autofocus />
          </div>
          <div class="field">
            <label>Confirm Password</label>
            <input v-model="confirmPassword" type="password" placeholder="Repeat password" />
          </div>
          <button type="submit" :disabled="loading || !newPassword || newPassword !== confirmPassword || newPassword.length < 6" class="btn-login">
            {{ loading ? 'Resetting...' : 'Reset Password' }}
          </button>
          <router-link to="/login" class="btn-back" style="display:block;text-align:center;text-decoration:none;margin-top:8px">Back to Login</router-link>
        </form>
      </div>

      <!-- Forgot form (no token) -->
      <div v-else>
        <p class="subtitle">Enter your email to receive a reset link</p>
        <div v-if="error" class="error-msg">{{ error }}</div>
        <div v-if="sent" class="sent-msg">{{ sent }}</div>
        <form v-if="!sent" @submit.prevent="handleForgot">
          <div class="field">
            <label>Email Address</label>
            <input v-model="email" type="email" placeholder="admin@example.com" autofocus />
          </div>
          <button type="submit" :disabled="loading || !email" class="btn-login">
            {{ loading ? 'Sending...' : 'Send Reset Link' }}
          </button>
          <router-link to="/login" class="btn-back" style="display:block;text-align:center;text-decoration:none;margin-top:8px">Back to Login</router-link>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import axios from 'axios'

const route = useRoute()
const token = ref('')
const email = ref('')
const newPassword = ref('')
const confirmPassword = ref('')
const loading = ref(false)
const error = ref('')
const sent = ref('')
const success = ref('')

onMounted(() => {
  token.value = (route.query.token as string) || ''
})

async function handleForgot() {
  error.value = ''
  loading.value = true
  try {
    const { data } = await axios.post('/api/auth/forgot-password', { email: email.value })
    sent.value = data.message
  } catch (e: any) {
    error.value = e.response?.data?.error || 'Failed to send reset email'
  } finally {
    loading.value = false
  }
}

async function handleReset() {
  error.value = ''
  loading.value = true
  try {
    const { data } = await axios.post('/api/auth/reset-password', {
      token: token.value,
      new_password: newPassword.value,
    })
    success.value = data.message
  } catch (e: any) {
    error.value = e.response?.data?.error || 'Failed to reset password'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page {
  min-height: 100vh; display: flex; align-items: center; justify-content: center;
  background: var(--bg-body); position: relative;
}
.login-page::before {
  content: ''; position: absolute; inset: 0; pointer-events: none;
  background:
    radial-gradient(ellipse at 20% 50%, rgba(56, 189, 248, 0.08) 0%, transparent 50%),
    radial-gradient(ellipse at 80% 20%, rgba(129, 140, 248, 0.06) 0%, transparent 50%);
}
.login-card {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px;
  padding: 40px; width: 400px; max-width: 90vw; position: relative; z-index: 1;
  box-shadow: 0 8px 32px rgba(0,0,0,0.2);
}
.login-card h1 {
  font-size: 1.8rem; margin-bottom: 4px;
  background: linear-gradient(135deg, var(--brand), var(--brand-secondary, #818cf8));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
}
.subtitle { color: var(--text-muted); font-size: 0.9rem; margin-bottom: 24px; }
.field { margin-bottom: 16px; }
.field label { display: block; color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 6px; }
.field input {
  width: 100%; padding: 10px 14px; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 8px; color: var(--text-primary); font-size: 1rem;
}
.btn-login {
  width: 100%; padding: 12px; background: linear-gradient(135deg, var(--accent), var(--brand-secondary, #818cf8));
  color: #fff; border: none; border-radius: 8px; font-size: 1rem; cursor: pointer; font-weight: 500;
}
.btn-login:disabled { opacity: 0.5; cursor: not-allowed; }
.btn-back {
  width: 100%; padding: 10px; background: transparent; color: var(--text-muted);
  border: 1px solid var(--border); border-radius: 8px; cursor: pointer;
}
.error-msg {
  background: rgba(239,68,68,0.1); border: 1px solid #ef4444; color: #ef4444;
  padding: 10px 14px; border-radius: 8px; margin-bottom: 16px; font-size: 0.9rem;
}
.sent-msg {
  background: rgba(16,185,129,0.1); border: 1px solid #10b981; color: #10b981;
  padding: 10px 14px; border-radius: 8px; margin-bottom: 16px; font-size: 0.9rem;
}
</style>

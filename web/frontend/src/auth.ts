import { ref, computed } from 'vue'
import axios from 'axios'

const token = ref(localStorage.getItem('token') || '')
const user = ref<any>(JSON.parse(localStorage.getItem('user') || 'null'))
const mfaPending = ref(false)
const forcePasswordChange = ref(false)

export const isAuthenticated = computed(() => !!token.value && !!user.value)
export const currentUser = computed(() => user.value)

// Set auth header for all requests
axios.interceptors.request.use((config) => {
  if (token.value) {
    config.headers.Authorization = `Bearer ${token.value}`
  }
  return config
})

axios.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      logout()
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

export async function login(username: string, password: string): Promise<{ mfaRequired: boolean; mfaType?: string }> {
  const { data } = await axios.post('/api/auth/login', { username, password })
  token.value = data.token
  localStorage.setItem('token', data.token)

  if (data.mfa_required) {
    mfaPending.value = true
    return { mfaRequired: true, mfaType: data.mfa_type }
  }

  user.value = data.user
  localStorage.setItem('user', JSON.stringify(data.user))
  forcePasswordChange.value = data.force_password_change || false
  return { mfaRequired: false }
}

export async function verifyMFA(code: string) {
  const { data } = await axios.post('/api/auth/mfa-verify', { code })
  token.value = data.token
  user.value = data.user
  localStorage.setItem('token', data.token)
  localStorage.setItem('user', JSON.stringify(data.user))
  mfaPending.value = false
}

export { forcePasswordChange }

export function logout() {
  token.value = ''
  user.value = null
  mfaPending.value = false
  forcePasswordChange.value = false
  localStorage.removeItem('token')
  localStorage.removeItem('user')
}

export function isMFAPending() {
  return mfaPending.value
}

import { createApp } from 'vue'
import { createRouter, createWebHistory } from 'vue-router'
import App from './App.vue'
import Dashboard from './views/Dashboard.vue'
import QueryLog from './views/QueryLog.vue'
import Blocklists from './views/Blocklists.vue'
import Login from './views/Login.vue'
import Users from './views/Users.vue'
import Zones from './views/Zones.vue'
import Settings from './views/Settings.vue'
import ResetPassword from './views/ResetPassword.vue'
import { isAuthenticated, currentUser } from './auth'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', component: Login, meta: { public: true } },
    { path: '/reset-password', component: ResetPassword, meta: { public: true } },
    { path: '/', component: Dashboard },
    { path: '/logs', component: QueryLog },
    { path: '/blocklists', component: Blocklists },
    { path: '/zones', component: Zones },
    { path: '/settings', component: Settings, meta: { admin: true } },
    { path: '/users', component: Users, meta: { admin: true } },
  ]
})

router.beforeEach((to) => {
  if (!to.meta.public && !isAuthenticated.value) {
    return '/login'
  }
  if (to.meta.admin && currentUser.value?.role !== 'admin') {
    return '/'
  }
})

const app = createApp(App)
app.use(router)
app.mount('#app')

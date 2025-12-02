import '@/assets/style.css'

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import AdminApp from './AdminApp.vue'

const app = createApp(AdminApp)
app.use(createPinia())
app.mount('#admin-app')

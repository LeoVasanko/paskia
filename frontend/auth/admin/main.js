import { initThemeFromCache } from '@/utils/theme'
initThemeFromCache()

import '@/assets/style.css'

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import AdminApp from './AdminApp.vue'
import { initKeyboardNavigation } from '@/utils/keynav'

const app = createApp(AdminApp)
app.use(createPinia())
app.mount('#admin-app')
initKeyboardNavigation()

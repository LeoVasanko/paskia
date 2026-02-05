import { initThemeFromCache } from '@/utils/theme'
initThemeFromCache()

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import { initKeyboardNavigation } from '@/utils/keynav'

const app = createApp(App)

app.use(createPinia())

app.mount('#app')
initKeyboardNavigation()

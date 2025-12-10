import '@/assets/style.css'

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import { initKeyboardNavigation } from '@/utils/keynav'

const app = createApp(App)

app.use(createPinia())

app.mount('#app')
initKeyboardNavigation()

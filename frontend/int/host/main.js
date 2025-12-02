import '@/assets/style.css'

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import HostApp from './HostApp.vue'

const app = createApp(HostApp)

app.use(createPinia())

app.mount('#app')

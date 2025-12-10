import { createApp } from 'vue'
import App from './RestrictedForward.vue'
import '@/assets/style.css'
import { initKeyboardNavigation } from '@/utils/keynav'

createApp(App).mount('#app')
initKeyboardNavigation()

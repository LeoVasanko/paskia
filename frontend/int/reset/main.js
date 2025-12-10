import { createApp } from 'vue'
import ResetApp from './ResetApp.vue'
import '@/assets/style.css'
import { initKeyboardNavigation } from '@/utils/keynav'

createApp(ResetApp).mount('#app')
initKeyboardNavigation()

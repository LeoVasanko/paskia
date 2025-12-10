import { createApp } from 'vue'
import RestrictedApi from './RestrictedApi.vue'
import '@/assets/style.css'
import { initKeyboardNavigation } from '@/utils/keynav'

createApp(RestrictedApi).mount('#app')
initKeyboardNavigation()

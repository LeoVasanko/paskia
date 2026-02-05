import './theme.js'
import { createApp } from 'vue'
import RestrictedApi from './RestrictedApi.vue'
import { initKeyboardNavigation } from '@/utils/keynav'

createApp(RestrictedApi).mount('#app')
initKeyboardNavigation()

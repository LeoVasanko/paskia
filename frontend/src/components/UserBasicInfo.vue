<template>
  <div v-if="userLoaded" class="user-info">
    <h3 class="user-name-heading">
      <span class="icon">👤</span>
      <span v-if="!editingName" class="user-name-row">
        <span class="display-name" :title="name">{{ name }}</span>
        <button v-if="canEdit && updateEndpoint" class="mini-btn" @click="startEdit" title="Edit name">✏️</button>
      </span>
      <span v-else class="user-name-row editing">
        <input
          v-model="newName"
          class="name-input"
          :placeholder="name"
          :disabled="busy || loading"
          maxlength="64"
          @keyup.enter="saveName"
        />
        <button class="mini-btn" @click="saveName" :disabled="busy || loading" title="Save name">💾</button>
        <button class="mini-btn" @click="cancelEdit" :disabled="busy || loading" title="Cancel">✖</button>
      </span>
    </h3>
    <div v-if="orgDisplayName || roleName" class="org-role-sub">
      <div class="org-line" v-if="orgDisplayName">{{ orgDisplayName }}</div>
      <div class="role-line" v-if="roleName">{{ roleName }}</div>
    </div>
    <span><strong>Visits:</strong></span>
    <span>{{ visits || 0 }}</span>
    <span><strong>Registered:</strong></span>
    <span>{{ formatDate(createdAt) }}</span>
    <span><strong>Last seen:</strong></span>
    <span>{{ formatDate(lastSeen) }}</span>
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { formatDate } from '@/utils/helpers'

const props = defineProps({
  name: { type: String, required: true },
  visits: { type: [Number, String], default: 0 },
  createdAt: { type: [String, Number, Date], default: null },
  lastSeen: { type: [String, Number, Date], default: null },
  updateEndpoint: { type: String, default: null },
  canEdit: { type: Boolean, default: true },
  loading: { type: Boolean, default: false },
  orgDisplayName: { type: String, default: '' },
  roleName: { type: String, default: '' }
})

const emit = defineEmits(['saved'])
const authStore = useAuthStore()

const editingName = ref(false)
const newName = ref('')
const busy = ref(false)
const userLoaded = computed(() => !!props.name)

function startEdit() { editingName.value = true; newName.value = '' }
function cancelEdit() { editingName.value = false }
async function saveName() {
  if (!props.updateEndpoint) { editingName.value = false; return }
  try {
    busy.value = true
    authStore.isLoading = true
    const bodyName = newName.value.trim()
    if (!bodyName) { cancelEdit(); return }
    const res = await fetch(props.updateEndpoint, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ display_name: bodyName }) })
    let data = {}
    try { data = await res.json() } catch (_) {}
    if (!res.ok || data.detail) throw new Error(data.detail || 'Update failed')
    editingName.value = false
    authStore.showMessage('Name updated', 'success', 1500)
    emit('saved')
  } catch (e) { authStore.showMessage(e.message || 'Failed to update name', 'error') }
  finally { busy.value = false; authStore.isLoading = false }
}
watch(() => props.name, () => { if (!props.name) editingName.value = false })
</script>

<style scoped>
.user-info { display: grid; grid-template-columns: auto 1fr; gap: 10px; }
.user-info h3 { grid-column: span 2; }
.org-role-sub { grid-column: span 2; display:flex; flex-direction:column; margin: -0.15rem 0 0.25rem; }
.org-line { font-size: .7rem; font-weight:600; line-height:1.1; }
.role-line { font-size:.6rem; color:#555; line-height:1.1; }
.user-info span { text-align: left; }
.user-name-heading { display: flex; align-items: center; gap: 0.4rem; flex-wrap: wrap; margin: 0 0 0.25rem 0; }
.user-name-row { display: inline-flex; align-items: center; gap: 0.35rem; max-width: 100%; }
.user-name-row.editing { flex: 1 1 auto; }
.icon { flex: 0 0 auto; }
.display-name { font-weight: 600; font-size: 1.05em; line-height: 1.2; max-width: 14ch; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.name-input { width: auto; flex: 1 1 140px; min-width: 120px; padding: 6px 8px; font-size: 0.9em; border: 1px solid #a9c5d6; border-radius: 6px; }
.user-name-heading .name-input { width: auto; }
.name-input:focus { outline: 2px solid #667eea55; border-color: #667eea; }
.mini-btn { width: auto; padding: 4px 6px; margin: 0; font-size: 0.75em; line-height: 1; background: #eef5fa; border: 1px solid #b7d2e3; border-radius: 6px; cursor: pointer; transition: background 0.2s, transform 0.15s; }
.mini-btn:hover:not(:disabled) { background: #dcecf6; }
.mini-btn:active:not(:disabled) { transform: translateY(1px); }
.mini-btn:disabled { opacity: 0.5; cursor: not-allowed; }
@media (max-width: 480px) { .user-name-heading { flex-direction: column; align-items: flex-start; } .user-name-row.editing { width: 100%; } .display-name { max-width: 100%; } }
</style>

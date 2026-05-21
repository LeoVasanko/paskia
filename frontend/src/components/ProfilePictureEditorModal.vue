<template>
  <Modal panel-class="modal-panel--avatar" @close="closeEditor">
    <h3>{{ title }}</h3>
    <input
      ref="pictureInput"
      type="file"
      accept="image/*"
      class="profile-picture-editor-input"
      :disabled="saving"
      @change="handlePictureSelected"
    />
    <div ref="picturePreview" class="profile-picture-editor-preview" :style="previewStyle">
      <img
        v-if="editorImageUrl && displayMetrics"
        :src="editorImageUrl"
        alt=""
        class="profile-picture-editor-image"
        :style="editorImageStyle"
      />
      <img
        v-if="editorImageUrl && displayMetrics"
        :src="editorImageUrl"
        alt=""
        class="profile-picture-editor-image profile-picture-editor-image--overlay"
        :style="editorOverlayStyle"
      />
      <div
        v-if="editorImageUrl && displayMetrics"
        class="profile-picture-editor-crop"
        :style="cropBoxStyle"
        @pointerdown="startMove"
      >
        <div class="profile-picture-editor-guides" aria-hidden="true">
          <div class="profile-picture-editor-guide profile-picture-editor-guide--circle"></div>
          <div class="profile-picture-editor-guide profile-picture-editor-guide--eyes"></div>
          <div class="profile-picture-editor-guide profile-picture-editor-guide--cheek-left"></div>
          <div class="profile-picture-editor-guide profile-picture-editor-guide--cheek-right"></div>
        </div>
        <button
          type="button"
          class="profile-picture-editor-handle profile-picture-editor-handle--nw"
          @pointerdown.stop="startResize($event, 'nw')"
        ></button>
        <button
          type="button"
          class="profile-picture-editor-handle profile-picture-editor-handle--ne"
          @pointerdown.stop="startResize($event, 'ne')"
        ></button>
        <button
          type="button"
          class="profile-picture-editor-handle profile-picture-editor-handle--sw"
          @pointerdown.stop="startResize($event, 'sw')"
        ></button>
        <button
          type="button"
          class="profile-picture-editor-handle profile-picture-editor-handle--se"
          @pointerdown.stop="startResize($event, 'se')"
        ></button>
      </div>
      <ProfilePicture
        v-else
        class="profile-picture-editor-trigger"
        :src="pictureUrl"
        :render-version="renderVersion"
        clickable
        :loading="saving"
        title="Choose profile picture"
        width="100%"
        height="100%"
        radius="0"
        fit="contain"
        fallback-size="5rem"
        @click="triggerPictureSelect"
      />
    </div>
    <div v-if="errorMessage" class="error small">{{ errorMessage }}</div>
    <div class="modal-actions">
      <button type="button" class="btn-secondary" :disabled="saving" @click="closeEditor">Back</button>
      <button
        v-if="!editorImageUrl && pictureUrl"
        type="button"
        class="btn-danger"
        :disabled="saving"
        @click="removePicture"
      >Delete</button>
      <button
        v-if="editorImageUrl"
        type="button"
        class="btn-primary"
        :disabled="saving"
        @click="savePicture"
      >Save</button>
    </div>
  </Modal>
</template>

<script setup>
import { computed, nextTick, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { apiJson } from 'paskia'
import { useAuthStore } from '@/stores/auth'
import Modal from '@/components/Modal.vue'
import ProfilePicture from '@/components/ProfilePicture.vue'

const AVATAR_UPLOAD_SIZE = 720
const MIN_CROP_SIZE = 36

const props = defineProps({
  endpoint: { type: String, required: true },
  pictureUrl: { type: String, default: null },
  renderVersion: { type: [Number, String], default: 0 },
  title: { type: String, default: 'Profile Picture' }
})

const emit = defineEmits(['close', 'updated'])
const authStore = useAuthStore()

const pictureInput = ref(null)
const picturePreview = ref(null)
const editorImage = ref(null)
const editorImageUrl = ref('')
const previewObjectUrl = ref(null)
const saving = ref(false)
const errorMessage = ref('')
const cropRect = reactive({ x: 0, y: 0, size: 0 })
const previewRect = reactive({ width: 0, height: 0 })
const viewportSize = reactive({ width: 0, height: 0 })
let dragState = null
let previewObserver = null

onMounted(async () => {
  viewportSize.width = window.innerWidth
  viewportSize.height = window.innerHeight
  window.addEventListener('pointermove', handlePointerMove)
  window.addEventListener('pointerup', endPointerInteraction)
  window.addEventListener('resize', syncPreviewRect)
  await nextTick()
  syncPreviewRect()
  if (picturePreview.value && typeof ResizeObserver !== 'undefined') {
    previewObserver = new ResizeObserver(() => syncPreviewRect())
    previewObserver.observe(picturePreview.value)
  }
})

onUnmounted(() => {
  window.removeEventListener('pointermove', handlePointerMove)
  window.removeEventListener('pointerup', endPointerInteraction)
  window.removeEventListener('resize', syncPreviewRect)
  previewObserver?.disconnect()
  clearPreviewObjectUrl()
})

watch(editorImage, async (image) => {
  if (!image) return
  await nextTick()
  syncPreviewRect()
  initializeCrop()
})

const clearPreviewObjectUrl = () => {
  if (!previewObjectUrl.value) return
  URL.revokeObjectURL(previewObjectUrl.value)
  previewObjectUrl.value = null
}

const resetEditor = () => {
  clearPreviewObjectUrl()
  editorImage.value = null
  editorImageUrl.value = ''
  cropRect.x = 0
  cropRect.y = 0
  cropRect.size = 0
  errorMessage.value = ''
  if (pictureInput.value) pictureInput.value.value = ''
}

const syncPreviewRect = () => {
  viewportSize.width = window.innerWidth
  viewportSize.height = window.innerHeight
  const element = picturePreview.value
  if (!element) return
  previewRect.width = element.clientWidth
  previewRect.height = element.clientHeight
}

const previewStyle = computed(() => {
  const image = editorImage.value
  if (!image) {
    const size = Math.min(viewportSize.width * 0.72, viewportSize.height * 0.42, 352)
    return {
      width: `${Math.max(160, Math.round(size))}px`,
      height: `${Math.max(160, Math.round(size))}px`
    }
  }

  const maxWidth = Math.min(viewportSize.width * 0.88, 928)
  const maxHeight = Math.min(viewportSize.height * 0.62, 620)
  const scale = Math.min(maxWidth / image.naturalWidth, maxHeight / image.naturalHeight)

  return {
    width: `${Math.max(1, Math.round(image.naturalWidth * scale))}px`,
    height: `${Math.max(1, Math.round(image.naturalHeight * scale))}px`
  }
})

const displayMetrics = computed(() => {
  const image = editorImage.value
  if (!image || !previewRect.width || !previewRect.height) return null
  const scale = Math.min(previewRect.width / image.naturalWidth, previewRect.height / image.naturalHeight)
  const width = image.naturalWidth * scale
  const height = image.naturalHeight * scale
  return {
    x: (previewRect.width - width) / 2,
    y: (previewRect.height - height) / 2,
    width,
    height
  }
})

const editorImageStyle = computed(() => {
  const metrics = displayMetrics.value
  if (!metrics) return null
  return {
    width: `${metrics.width}px`,
    height: `${metrics.height}px`,
    left: `${metrics.x}px`,
    top: `${metrics.y}px`
  }
})

const editorOverlayStyle = computed(() => {
  const metrics = displayMetrics.value
  if (!metrics || !cropRect.size) return editorImageStyle.value

  const left = cropRect.x
  const top = cropRect.y
  const right = cropRect.x + cropRect.size
  const bottom = cropRect.y + cropRect.size

  return {
    ...editorImageStyle.value,
    clipPath: `polygon(evenodd, 0 0, 100% 0, 100% 100%, 0 100%, 0 0, ${left}px ${top}px, ${left}px ${bottom}px, ${right}px ${bottom}px, ${right}px ${top}px, ${left}px ${top}px)`
  }
})

const cropBoxStyle = computed(() => {
  const metrics = displayMetrics.value
  if (!metrics || !cropRect.size) return null
  return {
    left: `${metrics.x + cropRect.x}px`,
    top: `${metrics.y + cropRect.y}px`,
    width: `${cropRect.size}px`,
    height: `${cropRect.size}px`
  }
})

const initializeCrop = () => {
  const metrics = displayMetrics.value
  if (!metrics) return
  const size = Math.min(metrics.width, metrics.height)
  cropRect.size = size
  cropRect.x = (metrics.width - size) / 2
  cropRect.y = (metrics.height - size) / 2
}

const triggerPictureSelect = () => {
  pictureInput.value?.click()
}

const handlePictureSelected = async (event) => {
  const nextFile = event.target.files?.[0] || null
  resetEditor()
  if (!nextFile) return

  previewObjectUrl.value = URL.createObjectURL(nextFile)
  editorImageUrl.value = previewObjectUrl.value
  const image = new Image()
  image.decoding = 'async'
  image.src = editorImageUrl.value
  try {
    await image.decode()
    editorImage.value = image
  } catch {
    errorMessage.value = 'Failed to load image'
    resetEditor()
  }
}

const startMove = (event) => {
  if (!displayMetrics.value || saving.value) return
  event.preventDefault()
  dragState = {
    mode: 'move',
    startX: event.clientX,
    startY: event.clientY,
    initialX: cropRect.x,
    initialY: cropRect.y,
    initialSize: cropRect.size
  }
}

const startResize = (event, handle) => {
  if (!displayMetrics.value || saving.value) return
  event.preventDefault()
  dragState = {
    mode: 'resize',
    handle,
    startX: event.clientX,
    startY: event.clientY,
    initialX: cropRect.x,
    initialY: cropRect.y,
    initialSize: cropRect.size
  }
}

const handlePointerMove = (event) => {
  if (!dragState) return
  const metrics = displayMetrics.value
  if (!metrics) return

  const dx = event.clientX - dragState.startX
  const dy = event.clientY - dragState.startY

  if (dragState.mode === 'move') {
    cropRect.x = Math.max(0, Math.min(metrics.width - dragState.initialSize, dragState.initialX + dx))
    cropRect.y = Math.max(0, Math.min(metrics.height - dragState.initialSize, dragState.initialY + dy))
    return
  }

  const directionMap = {
    nw: { deltaX: -1, deltaY: -1 },
    ne: { deltaX: 1, deltaY: -1 },
    sw: { deltaX: -1, deltaY: 1 },
    se: { deltaX: 1, deltaY: 1 }
  }
  const direction = directionMap[dragState.handle]
  if (!direction) return

  const delta = Math.max(dx * direction.deltaX, dy * direction.deltaY)
  const nextSize = Math.max(
    MIN_CROP_SIZE,
    Math.min(getResizeLimit(metrics, dragState), dragState.initialSize + delta)
  )

  applyResize(dragState, nextSize)
}

const endPointerInteraction = () => {
  dragState = null
}

const getResizeLimit = (metrics, state) => {
  const { initialX, initialY, initialSize, handle } = state

  if (handle === 'nw') return Math.min(initialX + initialSize, initialY + initialSize)
  if (handle === 'ne') return Math.min(metrics.width - initialX, initialY + initialSize)
  if (handle === 'sw') return Math.min(initialX + initialSize, metrics.height - initialY)
  return Math.min(metrics.width - initialX, metrics.height - initialY)
}

const applyResize = (state, size) => {
  const { initialX, initialY, initialSize, handle } = state

  if (handle === 'nw') {
    cropRect.x = initialX + initialSize - size
    cropRect.y = initialY + initialSize - size
    cropRect.size = size
    return
  }

  if (handle === 'ne') {
    cropRect.x = initialX
    cropRect.y = initialY + initialSize - size
    cropRect.size = size
    return
  }

  if (handle === 'sw') {
    cropRect.x = initialX + initialSize - size
    cropRect.y = initialY
    cropRect.size = size
    return
  }

  cropRect.x = initialX
  cropRect.y = initialY
  cropRect.size = size
}

const renderPictureBlob = async () => {
  const image = editorImage.value
  if (!image) throw new Error('No image selected')
  const metrics = displayMetrics.value
  if (!metrics || !cropRect.size) throw new Error('Crop selection unavailable')

  const canvas = document.createElement('canvas')
  canvas.width = AVATAR_UPLOAD_SIZE
  canvas.height = AVATAR_UPLOAD_SIZE
  const context = canvas.getContext('2d')
  if (!context) throw new Error('Canvas unavailable')

  const sourceScale = image.naturalWidth / metrics.width
  const sourceX = cropRect.x * sourceScale
  const sourceY = cropRect.y * sourceScale
  const sourceSize = cropRect.size * sourceScale
  context.drawImage(image, sourceX, sourceY, sourceSize, sourceSize, 0, 0, AVATAR_UPLOAD_SIZE, AVATAR_UPLOAD_SIZE)

  return await new Promise((resolve, reject) => {
    canvas.toBlob((blob) => {
      if (!blob) {
        reject(new Error('Failed to export cropped picture'))
        return
      }
      resolve(blob)
    }, 'image/webp', 0.9)
  })
}

const reloadPictureFromCache = async () => {
  const response = await fetch(props.endpoint, {
    method: 'GET',
    credentials: 'same-origin',
    cache: 'reload'
  })
  if (!response.ok) throw new Error('Failed to refresh profile picture')
}

const savePicture = async () => {
  try {
    saving.value = true
    errorMessage.value = ''
    const blob = await renderPictureBlob()
    const formData = new FormData()
    formData.append('file', blob, 'profile.webp')
    await apiJson(props.endpoint, { method: 'PUT', body: formData })
    await reloadPictureFromCache()
    authStore.showMessage('Profile picture updated.', 'success', 3000)
    emit('updated')
    closeEditor()
  } catch (error) {
    errorMessage.value = error.message || 'Failed to update profile picture'
  } finally {
    saving.value = false
  }
}

const removePicture = async () => {
  try {
    saving.value = true
    errorMessage.value = ''
    await apiJson(props.endpoint, { method: 'DELETE' })
    authStore.showMessage('Profile picture removed.', 'success', 3000)
    emit('updated')
    closeEditor()
  } catch (error) {
    errorMessage.value = error.message || 'Failed to remove profile picture'
  } finally {
    saving.value = false
  }
}

const closeEditor = () => {
  resetEditor()
  emit('close')
}
</script>

<style scoped>
.profile-picture-editor-input { display: none; }
.profile-picture-editor-preview { position: relative; display: flex; justify-content: center; align-items: center; width: auto; max-width: min(58rem, 88vw); min-height: 0; margin: 0 auto; overflow: visible; }
.profile-picture-editor-trigger { min-width: 0; }
.profile-picture-editor-image { position: absolute; user-select: none; pointer-events: none; object-fit: contain; }
.profile-picture-editor-image--overlay { filter: grayscale(0.45) saturate(0.7) brightness(0.68); }
.profile-picture-editor-crop { position: absolute; border: 2px solid white; cursor: move; touch-action: none; }
.profile-picture-editor-guides { position: absolute; inset: 0; pointer-events: none; }
.profile-picture-editor-guide { position: absolute; border-color: rgba(255, 255, 255, 0.52); }
.profile-picture-editor-guide--circle { inset: 0; border: 1.5px solid rgba(255, 255, 255, 0.62); border-radius: 999px; box-shadow: 0 0 0 1px rgba(0, 0, 0, 0.18); }
.profile-picture-editor-guide--eyes { left: 18%; right: 18%; top: 38%; border-top: 1.5px solid rgba(255, 255, 255, 0.56); }
.profile-picture-editor-guide--cheek-left { top: 24%; bottom: 18%; left: 24%; border-left: 1.5px solid rgba(255, 255, 255, 0.48); }
.profile-picture-editor-guide--cheek-right { top: 24%; bottom: 18%; right: 24%; border-right: 1.5px solid rgba(255, 255, 255, 0.48); }
.profile-picture-editor-handle { position: absolute; width: 1.1rem; height: 1.1rem; border-radius: 999px; border: 2px solid white; background: var(--color-accent); padding: 0; }
.profile-picture-editor-handle--nw { left: -0.55rem; top: -0.55rem; cursor: nwse-resize; }
.profile-picture-editor-handle--ne { right: -0.55rem; top: -0.55rem; cursor: nesw-resize; }
.profile-picture-editor-handle--sw { left: -0.55rem; bottom: -0.55rem; cursor: nesw-resize; }
.profile-picture-editor-handle--se { right: -0.55rem; bottom: -0.55rem; cursor: nwse-resize; }
:deep(.modal-panel--avatar) { width: fit-content; max-width: min(58rem, 94vw); }
@media (max-width: 720px) {
  .profile-picture-editor-preview { max-width: 100%; }
}
</style>

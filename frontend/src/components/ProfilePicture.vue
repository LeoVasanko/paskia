<template>
  <component
    :is="rootTag"
    v-bind="rootAttrs"
    class="profile-picture"
    :class="{ 'profile-picture-btn': clickable }"
    :style="pictureStyle"
    @click="handleClick"
  >
    <img
      v-if="showPicture"
      :key="`${src || 'none'}:${renderVersion}`"
      :src="src"
      alt=""
      class="profile-picture-image"
      @error="handleError"
    />
    <img
      v-else
      :src="profileGeneric"
      alt=""
      class="profile-picture-fallback"
    />
  </component>
</template>

<script setup>
import profileGeneric from '@/assets/profile-generic.svg'
import { computed, ref, watch } from 'vue'

const props = defineProps({
  src: { type: String, default: null },
  clickable: { type: Boolean, default: false },
  loading: { type: Boolean, default: false },
  title: { type: String, default: '' },
  renderVersion: { type: [Number, String], default: 0 },
  width: { type: String, default: '3rem' },
  height: { type: String, default: '3rem' },
  radius: { type: String, default: '0.9rem' },
  fit: { type: String, default: 'cover' },
  filter: { type: String, default: 'none' },
  fallbackSize: { type: String, default: '2em' }
})

const emit = defineEmits(['click'])
const pictureAvailable = ref(true)

const rootTag = computed(() => (props.clickable ? 'button' : 'div'))
const showPicture = computed(() => !!props.src && pictureAvailable.value)
const pictureStyle = computed(() => ({
  '--profile-picture-width': props.width,
  '--profile-picture-height': props.height,
  '--profile-picture-radius': props.radius,
  '--profile-picture-fit': props.fit,
  '--profile-picture-filter': props.filter,
  '--profile-picture-fallback-size': props.fallbackSize
}))
const rootAttrs = computed(() => {
  if (!props.clickable) return { title: props.title || undefined }
  return {
    type: 'button',
    disabled: props.loading,
    title: props.title || undefined
  }
})

watch(() => props.src, () => {
  pictureAvailable.value = true
})

const handleError = () => {
  pictureAvailable.value = false
}

const handleClick = () => {
  if (!props.clickable || props.loading) return
  emit('click')
}
</script>

<style scoped>
.profile-picture {
  display: flex;
  align-items: center;
  justify-content: center;
  width: var(--profile-picture-width);
  height: var(--profile-picture-height);
  font-size: var(--profile-picture-fallback-size);
  line-height: 1;
  overflow: hidden;
  border-radius: var(--profile-picture-radius);
  background: transparent;
  flex-shrink: 0;
}

.profile-picture-btn {
  padding: 0;
  border: 0;
  transition: transform 0.12s ease, box-shadow 0.12s ease;
  cursor: pointer;
}

.profile-picture-btn:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: inset 0 0 0 1px var(--color-accent);
}

.profile-picture-btn:disabled {
  cursor: progress;
}

.profile-picture-image {
  width: 100%;
  height: 100%;
  object-fit: var(--profile-picture-fit);
  display: block;
  filter: var(--profile-picture-filter);
}

.profile-picture-fallback {
  width: 100%;
  height: 100%;
  object-fit: contain;
  display: block;
}
</style>

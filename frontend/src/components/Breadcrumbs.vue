<script setup>
import { computed, ref, onMounted, watch } from 'vue'
import { getDirection, navigateButtonRow } from '@/utils/keynav'

// Props:
// entries: Array<{ label:string, href:string }>
// showHome: include leading home icon (defaults true)
// homeHref: home link target (default '/')
const props = defineProps({
  entries: { type: Array, default: () => [] },
  showHome: { type: Boolean, default: true },
  homeHref: { type: String, default: '/' }
})

const navRef = ref(null)

const crumbs = computed(() => {
  const base = props.showHome ? [{ label: '🏠', href: props.homeHref }] : []
  return [...base, ...props.entries]
})

// Find the index of the crumb matching current location
const currentIndex = computed(() => {
  const currentHref = window.location.hash || window.location.pathname
  for (let i = crumbs.value.length - 1; i >= 0; i--) {
    const href = crumbs.value[i].href
    if (href === currentHref || (href && currentHref.startsWith(href))) {
      return i
    }
  }
  return crumbs.value.length - 1 // Default to last crumb
})

function handleFocusIn(event) {
  // When the nav receives focus, focus the current page's crumb
  if (event.target === navRef.value) {
    const links = navRef.value.querySelectorAll('a')
    const targetIndex = Math.min(currentIndex.value, links.length - 1)
    if (links[targetIndex]) {
      links[targetIndex].focus()
    }
  }
}

function handleKeydown(event) {
  const direction = getDirection(event)
  if (!direction) return

  if (direction === 'left' || direction === 'right') {
    event.preventDefault()
    navigateButtonRow(navRef.value, event.target, direction, { itemSelector: 'a' })
  }
  // Up/down are handled by parent component
}

// Expose method to focus the current crumb from parent
function focusCurrent() {
  const links = navRef.value?.querySelectorAll('a')
  if (links?.length) {
    const targetIndex = Math.min(currentIndex.value, links.length - 1)
    links[targetIndex]?.focus()
  }
}

defineExpose({ focusCurrent })
</script>

<template>
  <nav
    ref="navRef"
    class="breadcrumbs"
    aria-label="Breadcrumb"
    v-if="crumbs.length"
    tabindex="0"
    @focusin="handleFocusIn"
    @keydown="handleKeydown"
  >
    <ol>
      <li v-for="(c, idx) in crumbs" :key="idx">
        <a :href="c.href" tabindex="-1">{{ c.label }}</a>
        <span v-if="idx < crumbs.length - 1" class="sep"> — </span>
      </li>
    </ol>
  </nav>
</template>

<style scoped>
.breadcrumbs { margin: .25rem 0 .5rem; line-height:1.2; color: var(--color-text-muted); }
.breadcrumbs ol { list-style: none; padding: 0; margin: 0; display: flex; flex-wrap: wrap; align-items: center; gap: .25rem; }
.breadcrumbs li { display: inline-flex; align-items: center; gap: .25rem; font-size: .9rem; }
.breadcrumbs a { text-decoration: none; color: var(--color-link); padding: 0 .25rem; border-radius:4px; transition: color 0.2s ease, background 0.2s ease; }
.breadcrumbs .sep { color: var(--color-text-muted); margin: 0; }
</style>

<script setup>
import { computed } from 'vue'

// Props:
// entries: Array<{ label:string, href:string }>
// showHome: include leading home icon (defaults true)
// homeHref: home link target (default '/')
const props = defineProps({
  entries: { type: Array, default: () => [] },
  showHome: { type: Boolean, default: true },
  homeHref: { type: String, default: '/' }
})

const crumbs = computed(() => {
  const base = props.showHome ? [{ label: '🏠', href: props.homeHref }] : []
  return [...base, ...props.entries]
})
</script>

<template>
  <nav class="breadcrumbs" aria-label="Breadcrumb" v-if="crumbs.length">
    <ol>
      <li v-for="(c, idx) in crumbs" :key="idx">
        <a :href="c.href">{{ c.label }}</a>
        <span v-if="idx < crumbs.length - 1" class="sep"> — </span>
      </li>
    </ol>
  </nav>
</template>

<style scoped>
.breadcrumbs { margin: .25rem 0 .5rem; line-height:1.2; }
.breadcrumbs ol { list-style: none; padding: 0; margin: 0; display: flex; flex-wrap: wrap; align-items: center; }
.breadcrumbs li { display: inline-flex; align-items: center; }
.breadcrumbs a { text-decoration: none; color: #0366d6; padding: 0 .15rem; border-radius:4px; }
.breadcrumbs a:hover, .breadcrumbs a:focus { text-decoration: underline; }
.breadcrumbs .sep { color: #888; margin: 0 .1rem; }
@media (prefers-color-scheme: dark) {
  .breadcrumbs a { color: #4ea3ff; }
  .breadcrumbs .sep { color: #aaa; }
}
</style>

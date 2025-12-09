<template>
  <div class="pairing-entry">
    <form @submit.prevent="submitCode" class="pairing-form">
      <!-- Code input (shown when device info not yet received) -->
      <div v-if="!deviceInfo" class="input-row">
        <div class="input-wrapper" :class="{ 'has-error': serverError, 'is-complete': deviceInfo && !serverError, 'focused': isFocused }">
          <!-- Visual slot-machine display overlay -->
          <div class="slot-machine" :class="{ 'has-error': serverError, 'is-complete': deviceInfo && !serverError }" aria-hidden="true">
            <div v-for="(word, index) in displayWords" :key="index" class="slot-reel" :class="{ 'invalid-word': word.invalid, 'empty': !word.text && !word.typedPrefix }">
              <div class="slot-word">
                <template v-if="word.typedPrefix">
                  <span class="typed-prefix">{{ word.typedPrefix }}</span><span class="hint-suffix">{{ word.hintSuffix }}</span>
                  <span v-if="word.hasCursor" class="cursor-overlay" :style="{ '--cursor-pos': word.cursorCharIndex, '--word-len': word.wordLen }"></span>
                </template>
                <template v-else-if="word.text">
                  {{ word.text }}
                  <span v-if="word.hasCursor" class="cursor-overlay" :style="{ '--cursor-pos': word.cursorCharIndex, '--word-len': word.wordLen }"></span>
                </template>
                <template v-else>
                  <span v-if="word.hasCursor" class="cursor-overlay" :style="{ '--cursor-pos': 0, '--word-len': 0 }"></span>
                </template>
              </div>
            </div>
          </div>
          <!-- Hidden input for actual text entry -->
          <input
            ref="inputRef"
            v-model="code"
            type="text"
            :placeholder="placeholder"
            autocomplete="off"
            autocapitalize="none"
            autocorrect="off"
            spellcheck="false"
            class="pairing-input hidden-input"
            @input="handleInput"
            @keydown="deferUpdateCursor"
            @mouseup="updateCursorPos"
            @focus="isFocused = true"
            @blur="isFocused = false"
          />
        </div>
        <!-- Processing status beside input -->
        <div v-if="processingStatus" class="processing-status">
          <span class="processing-icon">{{ processingStatus === 'pow' ? '🔐' : '📡' }}</span>
          <span class="processing-spinner-small"></span>
        </div>
      </div>

      <!-- Device info display (shown when 3 words match a request) -->
      <div v-else-if="deviceInfo" class="device-info">
        <p class="device-permit-text">Permit {{ deviceInfo.action === 'register' ? 'registration' : 'login' }} to <strong>{{ deviceInfo.host }}</strong></p>
        <p class="device-meta">{{ deviceInfo.user_agent_pretty }}</p>

        <p v-if="error" class="error-message" style="margin-top: 0.5rem;">{{ error }}</p>

        <div class="button-row" style="margin-top: 0.75rem; display: flex; gap: 0.5rem;">
          <button
            type="button"
            class="btn-secondary"
            :disabled="loading"
            @click="deny"
            style="flex: 1;"
          >
            Deny
          </button>
          <button
            ref="submitBtnRef"
            type="submit"
            :disabled="loading"
            class="btn-primary"
            style="flex: 1;"
          >
            {{ loading ? 'Authenticating…' : 'Authorize' }}
          </button>
        </div>
      </div>
    </form>
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { startAuthentication } from '@simplewebauthn/browser'
import aWebSocket from '@/utils/awaitable-websocket'
import { b64dec, b64enc } from '@/utils/base64url'
import { getSettings } from '@/utils/settings'
import { getUniqueMatch, isValidWord, isValidPrefix } from '@/utils/wordlist'
import { solvePoW } from '@/utils/pow'
import { useAuthStore } from '@/stores/auth'

const props = defineProps({
  title: { type: String, default: 'Help Another Device Sign In' },
  description: { type: String, default: 'Enter the code shown on the device that needs to sign in.' },
  placeholder: { type: String, default: 'Enter three words' },
  action: { type: String, default: 'login' }, // 'login' or 'register'
})

const emit = defineEmits(['completed', 'error', 'cancelled', 'back', 'register', 'deviceInfoVisible'])

// State
const loading = ref(false)
const error = ref(null)
const settings = ref(null)
let ws = null
let authStore = null

// Try to get authStore (might fail if Pinia not installed in this app instance)
try { authStore = useAuthStore() } catch (e) { /* ignore */ }

const inputRef = ref(null)
const submitBtnRef = ref(null)
const code = ref('')
const isProcessing = ref(false)
const processingStatus = ref('')
const deviceInfo = ref(null)
const autocompleteHint = ref('')

// Watch deviceInfo and emit visibility change
watch(deviceInfo, (newVal) => {
  emit('deviceInfoVisible', !!newVal)
})

const hasInvalidWord = ref(false)
const serverError = ref(false)
const cursorPos = ref(0)
const isFocused = ref(false)
let wsConnecting = false
let currentChallenge = null
let currentWork = null
let powPromise = null
let powSolution = null
let lookupTimeout = null
let lastLookedUpCode = null

// --- Helpers ---

function showMessage(message, type = 'info', duration = 3000) {
  if (authStore) {
    authStore.showMessage(message, type, duration)
  }
}

async function fetchSettings() {
  try {
    const data = await getSettings()
    settings.value = data
  } catch (err) {
    console.warn('Unable to load settings', err)
  }
}

// --- Input Mode Logic ---

function getWordAtCursor(input, cursor) {
  if (!input || cursor < 0) return { word: '', start: 0, end: 0 }
  let start = cursor, end = cursor
  while (start > 0 && /[a-zA-Z]/.test(input[start - 1])) start--
  while (end < input.length && /[a-zA-Z]/.test(input[end])) end++
  return { word: input.slice(start, end), start, end }
}

function getWords(input) {
  return input.trim().split(/[.\s]+/).filter(w => w.length > 0)
}

function countCompleteWords(input) {
  const endsWithSeparator = /[.\s]$/.test(input)
  const words = getWords(input)
  return endsWithSeparator ? words.length : Math.max(0, words.length - 1)
}

function analyzeWords(input) {
  if (!input) return { valid: true, segments: [] }
  const segments = []
  const endsWithSeparator = /[.\s]$/.test(input)
  let match, regex = /([a-zA-Z]+)|([.\s]+)/g
  while ((match = regex.exec(input)) !== null) {
    if (match[1]) segments.push({ text: match[1], isWord: true, start: match.index })
    else if (match[2]) segments.push({ text: match[2], isWord: false, start: match.index })
  }
  const words = segments.filter(s => s.isWord)
  let allValid = true
  words.forEach((wordSeg, idx) => {
    const isLastWord = idx === words.length - 1
    const word = wordSeg.text.toLowerCase()
    if (isLastWord && !endsWithSeparator) wordSeg.invalid = !isValidPrefix(word)
    else wordSeg.invalid = !isValidWord(word)
    if (wordSeg.invalid) allValid = false
  })
  return { valid: allValid, segments }
}

const coloredSegments = computed(() => {
  const { segments } = analyzeWords(code.value)
  return segments.map(s => ({ text: s.text, invalid: s.invalid || false }))
})

function checkWordsValidity(input) { return analyzeWords(input).valid }
function allWordsValid(input) { return getWords(input).length > 0 && getWords(input).every(w => isValidWord(w)) }

// Get the current partial word being typed (not yet a complete word)
function getCurrentPartialWord(input) {
  const endsWithSeparator = /[.\s]$/.test(input)
  if (endsWithSeparator) return ''
  const match = input.match(/[a-zA-Z]+$/)
  return match ? match[0].toLowerCase() : ''
}

// Calculate cursor position in the normalized display (wordIndex, charIndex within word)
// Returns { wordIndex: number, charIndex: number } where charIndex is position within the word text
function calcDisplayCursor(input, rawCursorPos) {
  if (!input || rawCursorPos === 0) {
    return { wordIndex: 0, charIndex: 0 }
  }

  // Parse input to find word boundaries
  const beforeCursor = input.slice(0, rawCursorPos)
  const wordMatches = [...beforeCursor.matchAll(/[a-zA-Z]+/g)]

  // Check if cursor is in whitespace after words
  const endsWithSeparator = /[.\s]$/.test(beforeCursor)

  if (wordMatches.length === 0) {
    // No words before cursor, cursor is at start of first word
    return { wordIndex: 0, charIndex: 0 }
  }

  const lastMatch = wordMatches[wordMatches.length - 1]
  const lastMatchEnd = lastMatch.index + lastMatch[0].length

  if (endsWithSeparator || rawCursorPos > lastMatchEnd) {
    // Cursor is after the last word (in whitespace), so it's at start of next word
    return { wordIndex: Math.min(wordMatches.length, 2), charIndex: 0 }
  }

  // Cursor is within the last word
  const charIndex = rawCursorPos - lastMatch.index
  return { wordIndex: wordMatches.length - 1, charIndex: charIndex }
}

// Compute display words for slot-machine overlay (always 3 slots)
const displayWords = computed(() => {
  const words = getWords(code.value)
  const result = []

  // Get analysis for validation
  const { segments } = analyzeWords(code.value)
  const wordSegments = segments.filter(s => s.isWord)

  // Get current partial word and autocomplete hint
  const partialWord = getCurrentPartialWord(code.value)
  const hint = autocompleteHint.value
  const endsWithSeparator = /[.\s]$/.test(code.value)

  // Calculate where cursor should be displayed
  const cursor = calcDisplayCursor(code.value, cursorPos.value)

  // Always show exactly 3 slots
  for (let i = 0; i < 3; i++) {
    const isCursorSlot = cursor.wordIndex === i

    if (i < words.length) {
      const word = words[i].toLowerCase()
      const isInvalid = wordSegments[i]?.invalid || false
      const isLastWord = i === words.length - 1

      if (isLastWord && !endsWithSeparator && hint && partialWord) {
        // Show typed prefix + hint suffix in the same slot
        // Total visible length is the full hint word
        const totalLen = hint.length
        result.push({
          text: '',
          typedPrefix: partialWord,
          hintSuffix: hint.slice(partialWord.length),
          invalid: isInvalid,
          hasCursor: isCursorSlot,
          cursorCharIndex: isCursorSlot ? cursor.charIndex : -1,
          wordLen: totalLen
        })
      } else {
        // Complete word - show cursor at appropriate position
        result.push({
          text: word,
          invalid: isInvalid,
          hasCursor: isCursorSlot,
          cursorCharIndex: isCursorSlot ? cursor.charIndex : -1,
          wordLen: word.length
        })
      }
    } else {
      // Empty slot
      result.push({
        text: '',
        invalid: false,
        hasCursor: isCursorSlot,
        cursorCharIndex: 0,
        wordLen: 0
      })
    }
  }

  return result
})

const hasThreeValidWords = computed(() => {
  const words = getWords(code.value)
  return words.length === 3 && words.every(w => isValidWord(w))
})

function normalizeCode(input) {
  return input.trim().toLowerCase().split(/[.\s]+/).filter(w => w).join('.')
}

function startPowSolving() {
  if (!currentChallenge || powPromise) return
  const challenge = b64dec(currentChallenge)
  powPromise = solvePoW(challenge, currentWork).then(solution => {
    powSolution = solution
    powPromise = null
  })
}

async function getPowSolution() {
  if (powSolution) { const s = powSolution; powSolution = null; return s }
  if (powPromise) { await powPromise; const s = powSolution; powSolution = null; return s }
  if (!currentChallenge) throw new Error('No PoW challenge available')
  const challenge = b64dec(currentChallenge)
  return await solvePoW(challenge, currentWork)
}

function updateChallenge(pow) {
  if (pow?.challenge) {
    currentChallenge = pow.challenge
    currentWork = pow.work
    powSolution = null
    powPromise = null
    startPowSolving()
  }
}

async function ensureConnection() {
  if (ws || wsConnecting) return
  wsConnecting = true
  try {
    const authHost = settings.value?.auth_host
    const wsPath = '/auth/ws/remote-auth/permit'
    const wsUrl = authHost && location.host !== authHost ? `//${authHost}${wsPath}` : wsPath
    ws = await aWebSocket(wsUrl)
    const msg = await ws.receive_json()
    if (msg.status && msg.detail) throw new Error(msg.detail)
    if (!msg.pow?.challenge) throw new Error('Server did not send PoW challenge')
    updateChallenge(msg.pow)
  } catch (err) {
    console.error('WebSocket connection error:', err)
    ws = null
    throw err
  } finally {
    wsConnecting = false
  }
}

// Defer cursor position update to after browser processes the key
function deferUpdateCursor(event) {
  // Handle Tab/Space for autocomplete immediately
  if (event.key === 'Tab' || event.key === ' ' || event.key === 'Escape') {
    handleKeydown(event)
    return
  }
  // Defer cursor update to next tick
  setTimeout(updateCursorPos, 0)
}

// Update cursor position from input
function updateCursorPos() {
  cursorPos.value = inputRef.value?.selectionStart ?? code.value.length
}

function updateAutocomplete() {
  cursorPos.value = inputRef.value?.selectionStart ?? code.value.length
  const { word, end } = getWordAtCursor(code.value, cursorPos.value)
  const completeWordCount = countCompleteWords(code.value)
  if (completeWordCount >= 3 || !word || word.length < 1 || cursorPos.value !== end) {
    autocompleteHint.value = ''
    return
  }
  const match = getUniqueMatch(word.toLowerCase())
  if (match && match !== word.toLowerCase()) autocompleteHint.value = match
  else autocompleteHint.value = ''
}

function applyAutocomplete() {
  if (!autocompleteHint.value) return false
  const { word, start, end } = getWordAtCursor(code.value, cursorPos.value)
  if (!word) return false
  const before = code.value.slice(0, start)
  const wordsBefore = getWords(before).length
  const isThirdWord = wordsBefore === 2
  const suffix = isThirdWord ? '' : ' '
  const after = code.value.slice(end)
  code.value = before + autocompleteHint.value + suffix + after.trimStart()
  const newPos = start + autocompleteHint.value.length + suffix.length
  nextTick(() => {
    inputRef.value?.setSelectionRange(newPos, newPos)
    cursorPos.value = newPos
  })
  autocompleteHint.value = ''
  return true
}

// Try to split concatenated words (e.g., "alienalien" -> "alien alien")
function trySplitWords(input) {
  // Only process if there's a continuous string of letters at the end
  const match = input.match(/^(.*?)([a-zA-Z]+)$/)
  if (!match) return input

  const prefix = match[1]  // Everything before the letter sequence
  const letters = match[2].toLowerCase()

  // Try to find valid word boundaries in the letter sequence
  const foundWords = []
  let remaining = letters

  while (remaining.length > 0) {
    let foundWord = null

    // Try to find the longest valid word from the start
    for (let len = Math.min(remaining.length, 6); len >= 3; len--) {
      const candidate = remaining.slice(0, len)
      if (isValidWord(candidate)) {
        foundWord = candidate
        break
      }
    }

    if (foundWord) {
      foundWords.push(foundWord)
      remaining = remaining.slice(foundWord.length)

      // Stop after 3 words
      if (foundWords.length >= 3) {
        remaining = ''
        break
      }
    } else {
      // No valid word found, keep the remaining as-is
      foundWords.push(remaining)
      break
    }
  }

  // Only return split version if we found at least one complete word
  // and there's a clear boundary (more than one segment, or the segment is a complete word)
  if (foundWords.length > 1 || (foundWords.length === 1 && isValidWord(foundWords[0]) && remaining === '')) {
    return prefix + foundWords.join(' ')
  }

  return input
}

function handleInput() {
  // Immediately update cursor position
  cursorPos.value = inputRef.value?.selectionStart ?? code.value.length

  // First, try to auto-split concatenated words
  const splitCode = trySplitWords(code.value)
  if (splitCode !== code.value) {
    code.value = splitCode
    nextTick(() => {
      const newLen = splitCode.length
      inputRef.value?.setSelectionRange(newLen, newLen)
      cursorPos.value = newLen
    })
  }

  const words = getWords(code.value)
  if (words.length >= 3) {
    const normalized = words.slice(0, 3).join(' ')
    if (code.value !== normalized) {
      const cursorWasAtEnd = cursorPos.value >= code.value.length
      code.value = normalized
      if (cursorWasAtEnd) {
        nextTick(() => {
          inputRef.value?.setSelectionRange(normalized.length, normalized.length)
          cursorPos.value = normalized.length
        })
      }
    }
  }

  updateAutocomplete()
  if (lookupTimeout) { clearTimeout(lookupTimeout); lookupTimeout = null }
  deviceInfo.value = null
  error.value = null
  serverError.value = false
  hasInvalidWord.value = !checkWordsValidity(code.value)
  const currentWords = getWords(code.value)
  if (currentWords.length >= 1 && !ws && !wsConnecting) ensureConnection()
  if (currentWords.length === 3) {
    if (!allWordsValid(code.value)) return
    lookupTimeout = setTimeout(() => { lookupDeviceInfo() }, 150)
  }
}

async function lookupDeviceInfo() {
  if (isProcessing.value || loading.value) return
  if (!hasThreeValidWords.value) return
  const normalizedCode = normalizeCode(code.value)
  if (normalizedCode === lastLookedUpCode && deviceInfo.value) return

  isProcessing.value = true
  processingStatus.value = 'pow'
  error.value = null
  serverError.value = false

  try {
    await ensureConnection()
    if (!ws) throw new Error('Failed to connect')
    const solution = await getPowSolution()
    const powB64 = b64enc(solution)
    const currentCode = normalizeCode(code.value)
    if (!hasThreeValidWords.value) return
    processingStatus.value = 'server'
    ws.send_json({ code: currentCode, pow: powB64 })
    const res = await ws.receive_json()
    updateChallenge(res.pow)
    if (typeof res.status === 'number' && res.status >= 400) {
      showMessage(res.detail || 'Request failed', 'error')
      serverError.value = true
      deviceInfo.value = null
      lastLookedUpCode = null
      return
    }
    if (res.status === 'found' && res.host) {
      code.value = currentCode.replace(/\./g, ' ')
      deviceInfo.value = {
        host: res.host,
        user_agent_pretty: res.user_agent_pretty,
        client_ip: res.client_ip,
        action: res.action || 'login'
      }
      lastLookedUpCode = currentCode
      nextTick(() => { submitBtnRef.value?.focus() })
    } else {
      showMessage('Unexpected response from server', 'error')
      serverError.value = true
      deviceInfo.value = null
      lastLookedUpCode = null
    }
  } catch (err) {
    console.error('Lookup error:', err)
    showMessage(err.message || 'Lookup failed', 'error')
    serverError.value = true
    deviceInfo.value = null
    lastLookedUpCode = null
    if (ws) { ws.close(); ws = null }
  } finally {
    isProcessing.value = false
    processingStatus.value = ''
  }
}

function handleKeydown(event) {
  if (event.key === 'Escape') {
    code.value = ''
    handleInput()
    event.preventDefault()
    return
  }
  if (event.key === 'Tab') {
    if (autocompleteHint.value) {
      const applied = applyAutocomplete()
      if (applied) { event.preventDefault(); handleInput(); return }
    }
    if (code.value.trim()) event.preventDefault()
    return
  }
  if (event.key === ' ' && autocompleteHint.value) {
    const applied = applyAutocomplete()
    if (applied) { event.preventDefault(); handleInput() }
  }
}

async function submitCode() {
  if (!deviceInfo.value || loading.value) return
  loading.value = true
  error.value = null
  try {
    if (!ws) await ensureConnection()
    if (!ws) throw new Error('Failed to connect')
    const solution = await getPowSolution()
    const powB64 = b64enc(solution)
    ws.send_json({ authenticate: true, pow: powB64 })
    const res = await ws.receive_json()
    if (typeof res.status === 'number' && res.status >= 400) throw new Error(res.detail || 'Authentication failed')
    if (!res.optionsJSON) throw new Error(res.detail || 'Failed to get authentication options')
    const authResponse = await startAuthentication(res)
    ws.send_json(authResponse)
    const result = await ws.receive_json()
    if (typeof result.status === 'number' && result.status >= 400) throw new Error(result.detail || 'Authentication failed')
    if (result.status === 'success') {
      showMessage('Device authenticated successfully!', 'success', 3000)
      emit('completed')
      reset()
    } else {
      throw new Error(result.detail || 'Authentication failed')
    }
  } catch (err) {
    console.error('Pairing error:', err)
    const message = err.name === 'NotAllowedError'
      ? 'Passkey authentication was cancelled'
      : (err.message || 'Authentication failed')
    error.value = message
    // Don't show toast - error is shown in dialog
    emit('error', message)
  } finally {
    loading.value = false
    if (ws) { ws.close(); ws = null }
  }
}

async function deny() {
  // Send deny message to server before closing websocket
  if (ws) {
    try {
      ws.send_json({ deny: true })
      // Give the server a moment to process the denial
      await new Promise(resolve => setTimeout(resolve, 100))
    } catch (e) {
      console.error('Error sending deny message:', e)
    }
    ws.close()
    ws = null
  }

  // Reset to initial state
  reset()
}

function reset() {
  code.value = ''
  error.value = null
  serverError.value = false
  deviceInfo.value = null
  isProcessing.value = false
  processingStatus.value = ''
  autocompleteHint.value = ''
  hasInvalidWord.value = false
  lastLookedUpCode = null
  if (ws) { ws.close(); ws = null }
  currentChallenge = null
  currentWork = null
  powPromise = null
  powSolution = null
}

// --- Lifecycle ---

onMounted(async () => {
  await fetchSettings()
  // Initialize cursor position
  nextTick(() => {
    cursorPos.value = inputRef.value?.selectionStart ?? 0
  })
})

onUnmounted(() => {
  if (lookupTimeout) { clearTimeout(lookupTimeout); lookupTimeout = null }
  if (ws) { ws.close(); ws = null }
})

defineExpose({ reset, deny, code, handleInput, loading, error })
</script>

<style scoped>
/* Input Mode Styles */
.pairing-entry {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.pairing-form {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.input-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.input-wrapper {
  position: relative;
  display: flex;
  width: 280px;
  max-width: 100%;
}

/* Slot machine visual display (matches RemoteAuthRequest) */
.slot-machine {
  position: absolute;
  left: 0;
  top: 0;
  width: 100%;
  height: 100%;
  gap: 0;
  box-sizing: border-box;
  z-index: 1;
}

.slot-machine.has-error {
  /* Error background only shown when focused */
}

.input-wrapper.focused.has-error .slot-machine {
  background: var(--color-error-bg, rgba(239, 68, 68, 0.05));
}

.slot-machine.is-complete {
  /* Success state - no special styling */
}

.slot-reel {
  flex: 1 1 33.333%;
  overflow: visible;
}

.slot-reel:not(:last-child) {
  margin-right: 0.5rem;
}

.slot-word {
  font-size: 1.25rem;
  font-weight: 600;
  letter-spacing: 0.05em;
  text-align: center;
  width: 100%;
  color: var(--color-text);
  display: flex;
  align-items: center;
  justify-content: center;
  position: relative;
}

.slot-word .typed-prefix {
  color: var(--color-text);
}

.slot-word .hint-suffix {
  color: var(--color-text-muted);
  opacity: 0.6;
}

.cursor-overlay {
  position: absolute;
  width: 2px;
  height: 1.2em;
  background: var(--color-text);
  animation: none;
  pointer-events: none;
  /* Position based on character index - calculate from center of slot */
  left: calc(50% + (var(--cursor-pos) - var(--word-len, 0) / 2) * 0.65em);
  transform: translateX(-1px);
  opacity: 0;
}

.input-wrapper.focused .cursor-overlay {
  opacity: 1;
  animation: cursorBlink 1s ease-in-out infinite;
}

@keyframes cursorBlink {
  0%, 49% {
    opacity: 1;
  }
  50%, 100% {
    opacity: 0;
  }
}

.slot-reel.invalid-word .slot-word {
  color: var(--color-error, #ef4444);
}

.slot-reel.invalid-word .slot-word .typed-prefix {
  color: var(--color-error, #ef4444);
}

.slot-reel.invalid-word .cursor-overlay {
  background: var(--color-error, #ef4444);
}

.slot-reel.empty .slot-word {
  color: var(--color-text-muted);
}

/* Hidden input - keeps focus and handles keyboard input */
.pairing-input {
  flex: 1;
  width: 100%;
  height: 100%;
  padding: 0.875rem 1rem;
  font-size: 1rem;
  font-family: inherit;
  border: 1px solid transparent;
  border-radius: var(--radius-sm, 6px);
  background: transparent;
  color: transparent;
  caret-color: transparent;
  outline: none;
  box-sizing: border-box;
  position: relative;
  z-index: 0;
}

.pairing-input.hidden-input {
  color: transparent;
  caret-color: transparent;
}

.pairing-input:disabled {
  cursor: not-allowed;
}

.pairing-input::placeholder {
  color: transparent;
}

.processing-status {
  display: flex;
  align-items: center;
  gap: 0.25rem;
  font-size: 0.875rem;
  color: var(--color-text-muted);
}

.processing-icon {
  font-size: 0.875rem;
}

.processing-spinner-small {
  width: 12px;
  height: 12px;
  border: 2px solid var(--color-border);
  border-top-color: var(--color-primary);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.device-info {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.device-permit-text {
  margin: 0;
  font-size: 0.95rem;
  color: var(--color-text);
}

.device-meta {
  margin: 0;
  font-size: 0.8rem;
  color: var(--color-text-muted);
  font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
}

.error-message {
  margin: 0;
  font-size: 0.875rem;
  color: var(--color-error, #ef4444);
  margin-bottom: 1rem;
}
</style>

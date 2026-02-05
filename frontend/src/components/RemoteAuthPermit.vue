<template>
  <div class="pairing-entry">
    <form @submit.prevent="submitCode" class="pairing-form">
      <!-- Code input (shown when device info not yet received) -->
      <div v-if="!deviceInfo" class="input-row">
        <div class="input-wrapper" :class="{ 'has-error': serverError, 'is-complete': deviceInfo && !serverError, 'focused': isFocused, 'has-selection': hasSelection }">
          <!-- Visual slot-machine display overlay -->
          <div class="slot-machine" :class="{ 'has-error': serverError, 'is-complete': deviceInfo && !serverError }" aria-hidden="true">
            <div v-for="(word, index) in displayWords" :key="index" class="slot-reel" :class="{ 'invalid-word': word.invalid, 'empty': !word.text && !word.typedPrefix }">
              <div class="slot-word">
                <span v-if="word.selectionStartChar >= 0 && word.selectionEndChar > word.selectionStartChar"
                      class="selection-overlay"
                      :style="{ '--sel-start': word.selectionStartChar, '--sel-end': word.selectionEndChar, '--word-len': word.wordLen }"></span>
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
        <p class="device-meta">{{ deviceInfo.user_agent_pretty || '—' }}</p>

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
const selectionStart = ref(0)
const selectionEnd = ref(0)
const isFocused = ref(false)
const isDeleting = ref(false)
let previousCursorPos = 0
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

// Get words for display, splitting concatenated valid words (e.g., "alienfood" -> ["alien", "food"])
function getDisplayWords(input) {
  const rawWords = getWords(input)
  const result = []

  for (const rawWord of rawWords) {
    // Try to split this raw word into valid words
    let remaining = rawWord.toLowerCase()
    while (remaining.length > 0 && result.length < 3) {
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
        result.push(foundWord)
        remaining = remaining.slice(foundWord.length)
      } else {
        // No valid word found, keep the remaining as partial word
        result.push(remaining)
        break
      }
    }
    if (result.length >= 3) break
  }

  return result
}

function countCompleteWords(input) {
  const endsWithSeparator = /[.\s]$/.test(input)
  const words = getDisplayWords(input)
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
function allWordsValid(input) { return getDisplayWords(input).length > 0 && getDisplayWords(input).every(w => isValidWord(w)) }

// Get the current partial word being typed (not yet a complete word)
function getCurrentPartialWord(input) {
  const endsWithSeparator = /[.\s]$/.test(input)
  if (endsWithSeparator) return ''
  const match = input.match(/[a-zA-Z]+$/)
  return match ? match[0].toLowerCase() : ''
}

// Calculate cursor position in the normalized display (wordIndex, charIndex within word)
// Returns { wordIndex: number, charIndex: number } where charIndex is position within the word text
// This handles concatenated words like "alienfood" being displayed as "alien" + "food"
function calcDisplayCursor(input, rawCursorPos) {
  if (!input || rawCursorPos === 0) {
    return { wordIndex: 0, charIndex: 0 }
  }

  const beforeCursor = input.slice(0, rawCursorPos)
  const endsWithSeparator = /[.\s]$/.test(beforeCursor)

  // Get display words for the text before cursor
  const displayWordsBefore = getDisplayWords(beforeCursor)

  if (displayWordsBefore.length === 0) {
    return { wordIndex: 0, charIndex: 0 }
  }

  if (endsWithSeparator) {
    // Cursor is in whitespace after words, so it's at start of next word
    return { wordIndex: Math.min(displayWordsBefore.length, 2), charIndex: 0 }
  }

  // Cursor is within/after the last display word
  const lastDisplayWord = displayWordsBefore[displayWordsBefore.length - 1]
  const wordIndex = displayWordsBefore.length - 1

  // Find where in the original input this display word ends
  // by getting the full display words and comparing
  const fullDisplayWords = getDisplayWords(input)

  // Calculate char position within the word
  // The last display word from beforeCursor might be partial
  const charIndex = lastDisplayWord.length

  // If this word is a complete valid word and it's not the 3rd word (index 2),
  // show cursor at start of next slot - but only when typing forward, not when deleting
  if (wordIndex < 2 && !isDeleting.value) {
    if (isValidWord(lastDisplayWord)) {
      return { wordIndex: wordIndex + 1, charIndex: 0 }
    }
  }

  return { wordIndex: Math.min(wordIndex, 2), charIndex: charIndex }
}

// Calculate display cursor without the "advance to next word" logic (for selection bounds)
function calcDisplayCursorRaw(input, rawCursorPos) {
  if (!input || rawCursorPos === 0) {
    return { wordIndex: 0, charIndex: 0 }
  }

  const beforeCursor = input.slice(0, rawCursorPos)
  const endsWithSeparator = /[.\s]$/.test(beforeCursor)
  const displayWordsBefore = getDisplayWords(beforeCursor)

  if (displayWordsBefore.length === 0) {
    return { wordIndex: 0, charIndex: 0 }
  }

  if (endsWithSeparator) {
    return { wordIndex: Math.min(displayWordsBefore.length, 2), charIndex: 0 }
  }

  const lastDisplayWord = displayWordsBefore[displayWordsBefore.length - 1]
  const wordIndex = displayWordsBefore.length - 1
  return { wordIndex: Math.min(wordIndex, 2), charIndex: lastDisplayWord.length }
}

// Compute display words for slot-machine overlay (always 3 slots)
const displayWords = computed(() => {
  const words = getDisplayWords(code.value)
  const result = []

  // Get current partial word and autocomplete hint
  const partialWord = getCurrentPartialWord(code.value)
  const hint = autocompleteHint.value
  const endsWithSeparator = /[.\s]$/.test(code.value)

  // Calculate selection bounds (raw positions without advance logic)
  const hasSelectionNow = selectionStart.value !== selectionEnd.value
  const selStart = calcDisplayCursorRaw(code.value, Math.min(selectionStart.value, selectionEnd.value))
  const selEnd = calcDisplayCursorRaw(code.value, Math.max(selectionStart.value, selectionEnd.value))

  // Calculate where cursor should be displayed
  // Use raw position when there's a selection (cursor shows at active end without advance)
  // Use advance logic only when typing without selection
  const cursor = hasSelectionNow
    ? calcDisplayCursorRaw(code.value, cursorPos.value)
    : calcDisplayCursor(code.value, cursorPos.value)

  // Always show exactly 3 slots
  for (let i = 0; i < 3; i++) {
    const isCursorSlot = cursor.wordIndex === i

    // Calculate selection range for this word
    let selectionStartChar = -1
    let selectionEndChar = -1
    if (hasSelectionNow) {
      if (i > selStart.wordIndex && i < selEnd.wordIndex) {
        // Entire word is selected
        selectionStartChar = 0
        selectionEndChar = words[i]?.length ?? 0
      } else if (i === selStart.wordIndex && i === selEnd.wordIndex) {
        // Selection starts and ends in this word
        selectionStartChar = selStart.charIndex
        selectionEndChar = selEnd.charIndex
      } else if (i === selStart.wordIndex) {
        // Selection starts in this word
        selectionStartChar = selStart.charIndex
        selectionEndChar = words[i]?.length ?? 0
      } else if (i === selEnd.wordIndex) {
        // Selection ends in this word
        selectionStartChar = 0
        selectionEndChar = selEnd.charIndex
      }
    }

    if (i < words.length) {
      const word = words[i].toLowerCase()
      const isLastWord = i === words.length - 1
      // Validate: last word without separator can be a prefix, others must be complete words
      const isInvalid = (isLastWord && !endsWithSeparator) ? !isValidPrefix(word) : !isValidWord(word)

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
          wordLen: totalLen,
          selectionStartChar,
          selectionEndChar
        })
      } else {
        // Complete word - show cursor at appropriate position
        result.push({
          text: word,
          invalid: isInvalid,
          hasCursor: isCursorSlot,
          cursorCharIndex: isCursorSlot ? cursor.charIndex : -1,
          wordLen: word.length,
          selectionStartChar,
          selectionEndChar
        })
      }
    } else {
      // Empty slot
      result.push({
        text: '',
        invalid: false,
        hasCursor: isCursorSlot,
        cursorCharIndex: 0,
        wordLen: 0,
        selectionStartChar,
        selectionEndChar
      })
    }
  }

  return result
})

const hasSelection = computed(() => selectionStart.value !== selectionEnd.value)

const hasThreeValidWords = computed(() => {
  const words = getDisplayWords(code.value)
  return words.length === 3 && words.every(w => isValidWord(w))
})

function normalizeCode(input) {
  // Use display words to handle concatenated words like "alienfood" -> "alien.food"
  const words = getDisplayWords(input)
  return words.join('.')
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

function updateCursorPos() {
  const input = inputRef.value
  const start = input?.selectionStart ?? code.value.length
  const end = input?.selectionEnd ?? start

  // Track direction based on which end moved
  // If selection exists, cursor is at the end being moved (selectionDirection)
  const direction = input?.selectionDirection ?? 'none'
  const activeCursor = direction === 'backward' ? start : end

  isDeleting.value = activeCursor < previousCursorPos
  previousCursorPos = activeCursor
  cursorPos.value = activeCursor
  selectionEnd.value = end
  // Store start separately - cursorPos is the active end, we need both for selection
  selectionStart.value = start
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
  const wordsBefore = getDisplayWords(before).length
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

function handleInput() {
  cursorPos.value = inputRef.value?.selectionStart ?? code.value.length

  // Mobile fallback for autocomplete: if cursor is right after "prefix " (partial word + space),
  // replace the partial with the completed word. On desktop, keydown intercepts space before input,
  // but mobile soft keyboards often insert the space before we can catch it.
  const cursor = cursorPos.value
  const beforeCursor = code.value.slice(0, cursor)
  // Check if cursor is right after a space that follows a word
  const spaceMatch = beforeCursor.match(/([a-zA-Z]+) $/)
  if (spaceMatch) {
    const partialWord = spaceMatch[1].toLowerCase()
    const match = getUniqueMatch(partialWord)
    // Only autocomplete if it's not already a complete word and we have a unique match
    if (match && match !== partialWord && !isValidWord(partialWord)) {
      const wordStartPos = cursor - spaceMatch[0].length
      const beforeWord = code.value.slice(0, wordStartPos)
      const afterSpace = code.value.slice(cursor)
      const wordsBefore = getDisplayWords(beforeWord).length
      const isThirdWord = wordsBefore === 2
      const suffix = isThirdWord ? '' : ' '
      code.value = beforeWord + match + suffix + afterSpace
      const newPos = wordStartPos + match.length + suffix.length
      nextTick(() => {
        inputRef.value?.setSelectionRange(newPos, newPos)
        cursorPos.value = newPos
      })
    }
  }

  updateAutocomplete()
  if (lookupTimeout) { clearTimeout(lookupTimeout); lookupTimeout = null }
  deviceInfo.value = null
  error.value = null
  serverError.value = false
  hasInvalidWord.value = !checkWordsValidity(code.value)
  const currentWords = getDisplayWords(code.value)
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
  pointer-events: none;
}

.input-wrapper.focused.has-error .slot-machine {
  background: var(--color-error-bg, rgba(239, 68, 68, 0.05));
}

.slot-reel {
  flex: 1 1 33.333%;
  overflow: visible;
}

.slot-reel:not(:last-child) {
  margin-right: 0.5rem;
}

.slot-word {
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
  animation: cursorBlink 250ms alternate infinite;
}

.input-wrapper.focused.has-selection .cursor-overlay {
  animation: none;
}

.selection-overlay {
  position: absolute;
  height: 1.2em;
  background: var(--color-primary, #3b82f6);
  opacity: 0.3;
  pointer-events: none;
  /* Position based on character indices - calculate from center of slot */
  left: calc(50% + (var(--sel-start) - var(--word-len, 0) / 2) * 0.65em);
  width: calc((var(--sel-end) - var(--sel-start)) * 0.65em);
}

@keyframes cursorBlink {
  0%, 50% { opacity: 1; }
  80%, 100% { opacity: 0; }
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
  border-radius: var(--radius-sm, 6px);
  position: relative;
  z-index: 0;
}

.pairing-input.hidden-input {
  opacity: 0;
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

class AwaitableWebSocket extends WebSocket {
  #received = []
  #waiting = []
  #err = null
  #opened = false

  constructor(resolve, reject, url, protocols, binaryType) {
    // Support relative URLs even on old browsers that don't natively support them
    super(new URL(url, document.baseURI.replace(/^http/, 'ws')), protocols)
    this.binaryType = binaryType || 'blob'
    this.onopen = () => {
      this.#opened = true
      resolve(this)
    }
    this.onmessage = e => {
      if (this.#waiting.length) this.#waiting.shift().resolve(e.data)
      else this.#received.push(e.data)
    }
    this.onclose = e => {
      if (!this.#opened) {
        reject(new Error(`Failed to connect to server (code ${e.code})`))
        return
      }
      // Create user-friendly close messages
      let message
      if (e.wasClean) {
        // Standard close codes
        switch (e.code) {
          case 1000: message = 'Connection closed normally'; break
          case 1001: message = 'Server is going away'; break
          case 1002: message = 'Protocol error'; break
          case 1003: message = 'Unsupported data received'; break
          case 1006: message = 'Connection lost unexpectedly'; break
          case 1007: message = 'Invalid data received'; break
          case 1008: message = 'Policy violation'; break
          case 1009: message = 'Message too large'; break
          case 1010: message = 'Extension negotiation failed'; break
          case 1011: message = 'Server encountered an error'; break
          case 1012: message = 'Server is restarting'; break
          case 1013: message = 'Server is overloaded, try again later'; break
          case 1014: message = 'Bad gateway'; break
          case 1015: message = 'TLS handshake failed'; break
          default: message = `Connection closed (code ${e.code})`
        }
      } else {
        message = e.code === 1006
          ? 'Connection lost unexpectedly'
          : `Connection closed with error (code ${e.code})`
      }
      this.#err = new Error(message)
      this.#waiting.splice(0).forEach(p => p.reject(this.#err))
    }
  }

  receive() {
    // If we have a message already received, return it immediately
    if (this.#received.length) return Promise.resolve(this.#received.shift())
    // Wait for incoming messages, if we have an error, reject immediately
    if (this.#err) return Promise.reject(this.#err)
    return new Promise((resolve, reject) => this.#waiting.push({ resolve, reject }))
  }

  async receive_bytes() {
    const data = await this.receive()
    if (typeof data === 'string') {
      console.error("WebSocket received text data, expected a binary message", data)
      throw new Error("WebSocket received text data, expected a binary message")
    }
    return data instanceof Blob ? data.bytes() : new Uint8Array(data)
  }

  async receive_json() {
    const data = await this.receive()
    if (typeof data !== 'string') {
      console.error("WebSocket received binary data, expected JSON string", data)
      throw new Error("WebSocket received binary data, expected JSON string")
    }
    try {
      return JSON.parse(data)
    } catch (err) {
      console.error("Failed to parse JSON from WebSocket message", data, err)
      throw new Error("Failed to parse JSON from WebSocket message")
    }
  }

  send_json(data) {
    let jsonData
    try {
      jsonData = JSON.stringify(data)
    } catch (err) {
      throw new Error(`Failed to stringify data for WebSocket: ${err.message}`)
    }
    this.send(jsonData)
  }
}

// Construct an async WebSocket with await aWebSocket(url) - relative URLs OK
export default function aWebSocket(url, options = {}) {
  const { protocols, binaryType } = options
  return new Promise((resolve, reject) => {
    new AwaitableWebSocket(resolve, reject, url, protocols, binaryType)
  })
}

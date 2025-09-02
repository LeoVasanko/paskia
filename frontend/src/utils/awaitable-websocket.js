class AwaitableWebSocket extends WebSocket {
  #received = []
  #waiting = []
  #err = null
  #opened = false

  constructor(resolve, reject, url, protocols, binaryType) {
    super(url, protocols)
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
        reject(new Error(`WebSocket ${this.url} failed to connect, code ${e.code}`))
        return
      }
      this.#err = e.wasClean
        ? new Error(`Websocket ${this.url} closed ${e.code}`)
        : new Error(`WebSocket ${this.url} closed with error ${e.code}`)
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
    let parsed
    try {
      parsed = JSON.parse(data)
    } catch (err) {
      console.error("Failed to parse JSON from WebSocket message", data, err)
      throw new Error("Failed to parse JSON from WebSocket message")
    }
    if (parsed.detail) {
      throw new Error(`Server: ${parsed.detail}`)
    }
    return parsed
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

// Construct an async WebSocket with await aWebSocket(url) - supports relative URLs even with old browsers that don't
export default function aWebSocket(url, options = {}) {
  const { protocols, binaryType } = options
  return new Promise((resolve, reject) => {
    new AwaitableWebSocket(resolve, reject, new URL(url, location.href), protocols, binaryType)
  })
}

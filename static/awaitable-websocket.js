class AwaitableWebSocket extends WebSocket {
  #received = []
  #waiting = []
  #err = null
  #opened = false

  constructor(resolve, reject, url, protocols) {
    super(url, protocols)
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

  recv() {
    // If we have a message already received, return it immediately
    if (this.#received.length) return Promise.resolve(this.#received.shift())
    // Wait for incoming messages, if we have an error, reject immediately
    if (this.#err) return Promise.reject(this.#err)
    return new Promise((resolve, reject) => this.#waiting.push({ resolve, reject }))
  }
}

// Construct an async WebSocket with await aWebSocket(url)
function aWebSocket(url, protocols) {
  return new Promise((resolve, reject) => {
    new AwaitableWebSocket(resolve, reject, url, protocols)
  })
}

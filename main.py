import json
import uuid
from typing import Dict

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from webauthn import generate_registration_options, verify_registration_response
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

app = FastAPI(title="WebAuthn Registration Server")

# In-memory storage for challenges (in production, use Redis or similar)
active_challenges: Dict[str, str] = {}

# WebAuthn configuration
RP_ID = "localhost"
RP_NAME = "WebAuthn Demo"
ORIGIN = "http://localhost:8000"


class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.active_connections[client_id] = websocket

    def disconnect(self, client_id: str):
        if client_id in self.active_connections:
            del self.active_connections[client_id]

    async def send_message(self, message: dict, client_id: str):
        if client_id in self.active_connections:
            await self.active_connections[client_id].send_text(json.dumps(message))


manager = ConnectionManager()


@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    await manager.connect(websocket, client_id)
    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)

            if message["type"] == "registration_challenge":
                await handle_registration_challenge(message, client_id)
            elif message["type"] == "registration_response":
                await handle_registration_response(message, client_id)
            else:
                await manager.send_message(
                    {
                        "type": "error",
                        "message": f"Unknown message type: {message['type']}",
                    },
                    client_id,
                )

    except WebSocketDisconnect:
        manager.disconnect(client_id)


async def handle_registration_challenge(message: dict, client_id: str):
    """Handle registration challenge request"""
    try:
        username = message.get("username", "user@example.com")
        user_id = str(uuid.uuid4()).encode()

        # Generate registration options with Resident Key support
        options = generate_registration_options(
            rp_id=RP_ID,
            rp_name=RP_NAME,
            user_id=user_id,
            user_name=username,
            user_display_name=username,
            # Enable Resident Keys (discoverable credentials)
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
            # Support common algorithms
            supported_pub_key_algs=[
                COSEAlgorithmIdentifier.ECDSA_SHA_256,
                COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
            ],
        )

        # Store challenge for this client
        active_challenges[client_id] = options.challenge

        # Convert options to dict for JSON serialization
        options_dict = {
            "challenge": options.challenge,
            "rp": {
                "name": options.rp.name,
                "id": options.rp.id,
            },
            "user": {
                "id": options.user.id,
                "name": options.user.name,
                "displayName": options.user.display_name,
            },
            "pubKeyCredParams": [
                {"alg": param.alg, "type": param.type}
                for param in options.pub_key_cred_params
            ],
            "timeout": options.timeout,
            "attestation": options.attestation,
            "authenticatorSelection": {
                "residentKey": options.authenticator_selection.resident_key.value,
                "userVerification": options.authenticator_selection.user_verification.value,
            },
        }

        await manager.send_message(
            {"type": "registration_challenge_response", "options": options_dict},
            client_id,
        )

    except Exception as e:
        await manager.send_message(
            {"type": "error", "message": f"Failed to generate challenge: {str(e)}"},
            client_id,
        )


async def handle_registration_response(message: dict, client_id: str):
    """Handle registration response verification"""
    try:
        # Get the stored challenge
        if client_id not in active_challenges:
            await manager.send_message(
                {"type": "error", "message": "No active challenge found"}, client_id
            )
            return

        expected_challenge = active_challenges[client_id]
        credential = message["credential"]

        # Verify the registration response
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
        )

        if verification.verified:
            # Clean up the challenge
            del active_challenges[client_id]

            await manager.send_message(
                {
                    "type": "registration_success",
                    "message": "Registration successful!",
                    "credentialId": verification.credential_id,
                    "credentialPublicKey": verification.credential_public_key,
                },
                client_id,
            )
        else:
            await manager.send_message(
                {"type": "error", "message": "Registration verification failed"},
                client_id,
            )

    except Exception as e:
        await manager.send_message(
            {"type": "error", "message": f"Registration failed: {str(e)}"}, client_id
        )


# Serve static files
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
async def get_index():
    return HTMLResponse(
        content="""
<!DOCTYPE html>
<html>
<head>
    <title>WebAuthn Registration Demo</title>
    <script src="/static/simplewebauthn-browser.min.js"></script>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        .container { text-align: center; }
        button { padding: 10px 20px; margin: 10px; font-size: 16px; cursor: pointer; }
        .success { color: green; }
        .error { color: red; }
        .info { color: blue; }
        #log { text-align: left; background: #f5f5f5; padding: 10px; margin: 20px 0; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>WebAuthn Registration Demo</h1>
        <p>Test WebAuthn registration with Resident Keys support</p>
        
        <div>
            <label for="username">Username:</label>
            <input type="text" id="username" value="user@example.com" style="margin: 10px; padding: 5px;">
        </div>
        
        <button id="registerBtn">Register Passkey</button>
        
        <div id="status"></div>
        <div id="log"></div>
    </div>

    <script>
        const { startRegistration } = SimpleWebAuthnBrowser;
        
        // Generate a unique client ID
        const clientId = Math.random().toString(36).substring(7);
        
        // WebSocket connection
        const ws = new WebSocket(`ws://localhost:8000/ws/${clientId}`);
        
        const statusDiv = document.getElementById('status');
        const logDiv = document.getElementById('log');
        const registerBtn = document.getElementById('registerBtn');
        const usernameInput = document.getElementById('username');
        
        function log(message, type = 'info') {
            const timestamp = new Date().toLocaleTimeString();
            logDiv.innerHTML += `<div class="${type}">[${timestamp}] ${message}</div>`;
            logDiv.scrollTop = logDiv.scrollHeight;
        }
        
        function setStatus(message, type = 'info') {
            statusDiv.innerHTML = `<div class="${type}">${message}</div>`;
        }
        
        ws.onopen = function() {
            log('Connected to WebSocket server', 'success');
            setStatus('Ready for registration', 'success');
            registerBtn.disabled = false;
        };
        
        ws.onmessage = async function(event) {
            const message = JSON.parse(event.data);
            log(`Received: ${message.type}`);
            
            if (message.type === 'registration_challenge_response') {
                try {
                    log('Starting WebAuthn registration...');
                    setStatus('Touch your authenticator...', 'info');
                    
                    const attResp = await startRegistration(message.options);
                    
                    log('WebAuthn registration completed, verifying...');
                    setStatus('Verifying registration...', 'info');
                    
                    ws.send(JSON.stringify({
                        type: 'registration_response',
                        credential: attResp
                    }));
                    
                } catch (error) {
                    log(`Registration failed: ${error.message}`, 'error');
                    setStatus('Registration failed', 'error');
                    registerBtn.disabled = false;
                }
            } else if (message.type === 'registration_success') {
                log('Registration verified successfully!', 'success');
                setStatus('Registration successful! Passkey created.', 'success');
                registerBtn.disabled = false;
            } else if (message.type === 'error') {
                log(`Error: ${message.message}`, 'error');
                setStatus(`Error: ${message.message}`, 'error');
                registerBtn.disabled = false;
            }
        };
        
        ws.onerror = function(error) {
            log('WebSocket error: ' + error, 'error');
            setStatus('Connection error', 'error');
        };
        
        ws.onclose = function() {
            log('WebSocket connection closed', 'info');
            setStatus('Disconnected', 'error');
            registerBtn.disabled = true;
        };
        
        registerBtn.addEventListener('click', function() {
            const username = usernameInput.value.trim();
            if (!username) {
                alert('Please enter a username');
                return;
            }
            
            registerBtn.disabled = true;
            setStatus('Requesting registration challenge...', 'info');
            log(`Starting registration for: ${username}`);
            
            ws.send(JSON.stringify({
                type: 'registration_challenge',
                username: username
            }));
        });
        
        // Disable button until connection is ready
        registerBtn.disabled = true;
    </script>
</body>
</html>
    """
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)

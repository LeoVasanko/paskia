"""
WebAuthn handler class that combines registration and authentication functionality.

This module provides a unified interface for WebAuthn operations including:
- Registration challenge generation and verification
- Authentication challenge generation and verification
- Credential validation
"""

import json
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.authentication.verify_authentication_response import (
    VerifiedAuthentication,
)
from webauthn.helpers import (
    options_to_json,
    parse_authentication_credential_json,
    parse_registration_credential_json,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AuthenticationCredential,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)


@dataclass
class StoredCredential:
    """Credential data stored in the database."""

    credential_id: bytes
    user_id: UUID
    aaguid: UUID
    public_key: bytes
    sign_count: int
    created_at: datetime
    last_used: datetime | None = None
    last_verified: datetime | None = None


class Passkey:
    """WebAuthn handler for registration and authentication operations."""

    def __init__(
        self,
        rp_id: str,
        rp_name: str,
        origin: str,
        supported_pub_key_algs: list[COSEAlgorithmIdentifier] | None = None,
    ):
        """
        Initialize the WebAuthn handler.

        Args:
            rp_id: Your security domain (e.g. "example.com")
            rp_name: The relying party name (e.g., "My Application" - visible to users)
            origin: The origin URL of the application (e.g. "https://app.example.com"). Must be a subdomain or same as rp_id, with port and scheme but no path included.
            supported_pub_key_algs: List of supported COSE algorithms (default is EDDSA, ECDSA_SHA_256, RSASSA_PKCS1_v1_5_SHA_256).
        """
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.origin = origin
        self.supported_pub_key_algs = supported_pub_key_algs or [
            COSEAlgorithmIdentifier.EDDSA,
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ]

    ### Registration Methods ###

    def reg_generate_options(
        self,
        user_id: UUID,
        user_name: str,
        credential_ids: list[bytes] | None = None,
        **regopts,
    ) -> tuple[dict, bytes]:
        """
        Generate registration options for WebAuthn registration.

        Args:
            user_id: The user ID as bytes
            user_name: The username
            credential_ids: For an already authenticated user, a list of credential IDs
                associated with the account. This prevents accidentally adding another
                credential on an authenticator that already has one of the listed IDs.
            regopts: Additional arguments to generate_registration_options.

        Returns:
            JSON dict containing options to be sent to client,
            challenge bytes to keep during the registration process.
        """
        options = generate_registration_options(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            user_id=user_id.bytes,
            user_name=user_name,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
            exclude_credentials=_convert_credential_ids(credential_ids),
            supported_pub_key_algs=self.supported_pub_key_algs,
            **regopts,
        )
        return json.loads(options_to_json(options)), options.challenge

    def reg_verify(
        self,
        response_json: dict | str,
        expected_challenge: bytes,
        user_id: UUID,
    ) -> StoredCredential:
        """
        Verify registration response.

        Args:
            credential: The credential response from the client
            expected_challenge: The expected challenge bytes

        Returns:
            Registration verification result
        """
        credential = parse_registration_credential_json(response_json)
        registration = verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_origin=self.origin,
            expected_rp_id=self.rp_id,
        )
        return StoredCredential(
            credential_id=credential.raw_id,
            user_id=user_id,
            aaguid=UUID(registration.aaguid),
            public_key=registration.credential_public_key,
            sign_count=registration.sign_count,
            created_at=datetime.now(),
        )

    ### Authentication Methods ###

    async def auth_generate_options(
        self,
        *,
        user_verification_required=False,
        credential_ids: list[bytes] | None = None,
        **authopts,
    ) -> tuple[dict, bytes]:
        """
        Generate authentication options for WebAuthn authentication.

        Args:
            user_verification_required: The user will have to re-enter PIN or use biometrics for this operation. Useful when accessing security settings etc.
            credential_ids: For an already known user, a list of credential IDs associated with the account (less prompts during authentication).
            authopts: Additional arguments to generate_authentication_options.

        Returns:
            Tuple of (JSON to be sent to client, challenge bytes to store)
        """
        options = generate_authentication_options(
            rp_id=self.rp_id,
            user_verification=(
                UserVerificationRequirement.REQUIRED
                if user_verification_required
                else UserVerificationRequirement.PREFERRED
            ),
            allow_credentials=_convert_credential_ids(credential_ids),
            **authopts,
        )
        return json.loads(options_to_json(options)), options.challenge

    def auth_parse(self, response: dict | str) -> AuthenticationCredential:
        return parse_authentication_credential_json(response)

    async def auth_verify(
        self,
        credential: AuthenticationCredential,
        expected_challenge: bytes,
        stored_cred: StoredCredential,
    ) -> VerifiedAuthentication:
        """
        Verify authentication response against locally stored credential data.

        Args:
            credential: The authentication credential response from the client
            expected_challenge: The earlier generated challenge bytes
            stored_cred: The server stored credential record (modified by this function)
        """
        # Verify the authentication response
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_origin=self.origin,
            expected_rp_id=self.rp_id,
            credential_public_key=stored_cred.public_key,
            credential_current_sign_count=stored_cred.sign_count,
        )
        stored_cred.sign_count = verification.new_sign_count
        now = datetime.now()
        stored_cred.last_used = now
        if verification.user_verified:
            stored_cred.last_verified = now
        return verification


def _convert_credential_ids(
    credential_ids: list[bytes] | None,
) -> list[PublicKeyCredentialDescriptor] | None:
    """A helper to convert a list of credential IDs to PublicKeyCredentialDescriptor objects, or pass through None."""
    if credential_ids is None:
        return None
    return [PublicKeyCredentialDescriptor(id) for id in credential_ids]

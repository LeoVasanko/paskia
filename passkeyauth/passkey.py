"""
WebAuthn handler class that combines registration and authentication functionality.

This module provides a unified interface for WebAuthn operations including:
- Registration challenge generation and verification
- Authentication challenge generation and verification
- Credential validation
"""

import json

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
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
    RegistrationCredential,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from webauthn.registration.verify_registration_response import VerifiedRegistration


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
            rp_id: The relying party identifier
            rp_name: The relying party name
            origin: The origin URL of the application
            supported_pub_key_algs: List of supported COSE algorithms
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
        self, user_id: bytes, user_name: str, display_name="", **regopts
    ) -> tuple[dict, bytes]:
        """
        Generate registration options for WebAuthn registration.

        Args:
            user_id: The user ID as bytes
            user_name: The username
            display_name: The display name (defaults to user_name if empty)

        Returns:
            JSON dict containing options to be sent to client, challenge bytes to store
        """
        options = generate_registration_options(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            user_id=user_id,
            user_name=user_name,
            user_display_name=display_name or user_name,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
            supported_pub_key_algs=self.supported_pub_key_algs,
            **regopts,
        )
        return json.loads(options_to_json(options)), options.challenge

    @staticmethod
    def reg_credential(credential: dict | str) -> RegistrationCredential:
        return parse_registration_credential_json(credential)

    def reg_verify(
        self,
        credential: RegistrationCredential,
        expected_challenge: bytes,
    ) -> VerifiedRegistration:
        """
        Verify registration response.

        Args:
            credential: The credential response from the client
            expected_challenge: The expected challenge bytes

        Returns:
            Registration verification result
        """
        registration = verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_origin=self.origin,
            expected_rp_id=self.rp_id,
        )
        return registration

    ### Authentication Methods ###

    async def auth_generate_options(
        self, user_verification_required=False, **kwopts
    ) -> tuple[dict, bytes]:
        """
        Generate authentication options for WebAuthn authentication.

        Args:
            user_verification_required: The user will have to re-enter PIN or use biometrics for this operation. Useful when accessing security settings etc.
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
            **kwopts,
        )
        return json.loads(options_to_json(options)), options.challenge

    @staticmethod
    def auth_credential(credential: dict | str) -> AuthenticationCredential:
        """Convert the authentication credential from JSON to a dataclass instance."""
        return parse_authentication_credential_json(credential)

    async def auth_verify(
        self,
        credential: AuthenticationCredential,
        expected_challenge: bytes,
        stored_cred,
    ):
        """
        Verify authentication response against locally stored credential data.
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
        return verification

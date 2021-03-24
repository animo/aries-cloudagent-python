from asynctest import TestCase
from datetime import datetime

from ....wallet.base import KeyInfo
from ....wallet.crypto import KeyType
from ....did.did_key import DIDKey
from ....wallet.in_memory import InMemoryWallet
from ....core.in_memory import InMemoryProfile
from ...ld_proofs import (
    Ed25519Signature2018,
    Ed25519WalletKeyPair,
)
from ...vc_ld import (
    issue,
    verify_credential,
    create_presentation,
    sign_presentation,
    verify_presentation,
)
from ...tests.document_loader import custom_document_loader
from .test_credential import (
    CREDENTIAL_TEMPLATE,
    CREDENTIAL_ISSUED,
    CREDENTIAL_VERIFIED,
    PRESENTATION_SIGNED,
    PRESENTATION_UNSIGNED,
)


class TestLinkedDataVerifiableCredential(TestCase):
    test_seed = "testseed000000000000000000000001"
    test_seed2 = "testseed000000000000000000000002"
    issuer_key_info: KeyInfo = None

    async def setUp(self):
        self.profile = InMemoryProfile.test_profile()
        self.wallet = InMemoryWallet(self.profile)

        self.issuer_key_info = await self.wallet.create_signing_key(self.test_seed)
        self.issuer_verification_method = DIDKey.from_public_key_b58(
            self.issuer_key_info.verkey, KeyType.ED25519
        ).key_id

        self.holder_key_info = await self.wallet.create_signing_key(self.test_seed2)
        self.presentation_challenge = "2b1bbff6-e608-4368-bf84-67471b27e41c"

    async def test_issue(self):
        # Use different key pair and suite for signing and verification
        # as during verification a lot of information can be extracted
        # from the proof / document
        suite = Ed25519Signature2018(
            verification_method=self.issuer_verification_method,
            key_pair=Ed25519WalletKeyPair(
                wallet=self.wallet, public_key_base58=self.issuer_key_info.verkey
            ),
            date=datetime.strptime("2019-12-11T03:50:55Z", "%Y-%m-%dT%H:%M:%SZ"),
        )

        issued = await issue(
            credential=CREDENTIAL_TEMPLATE,
            suite=suite,
            document_loader=custom_document_loader,
        )

        assert issued == CREDENTIAL_ISSUED

    async def test_verify(self):
        # Verification requires lot less input parameters
        suite = Ed25519Signature2018(
            key_pair=Ed25519WalletKeyPair(wallet=self.wallet),
        )
        verified = await verify_credential(
            credential=CREDENTIAL_ISSUED,
            suites=[suite],
            document_loader=custom_document_loader,
        )

        assert verified == CREDENTIAL_VERIFIED

    async def test_create_presentation(self):
        # TODO: create presentation from subject id controller
        # TODO: create presentation with multiple credentials
        unsigned_presentation = await create_presentation(
            credentials=[CREDENTIAL_ISSUED]
        )

        suite = Ed25519Signature2018(
            verification_method=self.issuer_verification_method,
            key_pair=Ed25519WalletKeyPair(
                wallet=self.wallet, public_key_base58=self.issuer_key_info.verkey
            ),
            date=datetime.strptime("2020-12-11T03:50:55Z", "%Y-%m-%dT%H:%M:%SZ"),
        )

        assert unsigned_presentation == PRESENTATION_UNSIGNED

        presentation = await sign_presentation(
            presentation=unsigned_presentation,
            suite=suite,
            document_loader=custom_document_loader,
            challenge=self.presentation_challenge,
        )

        assert presentation == PRESENTATION_SIGNED

    async def test_create_presentation_same_subject(self):
        # TODO: subject is holder proof purpose or something?
        issuer_suite = Ed25519Signature2018(
            verification_method=self.issuer_verification_method,
            key_pair=Ed25519WalletKeyPair(
                wallet=self.wallet, public_key_base58=self.issuer_key_info.verkey
            ),
            date=datetime.strptime("2020-12-11T03:50:55Z", "%Y-%m-%dT%H:%M:%SZ"),
        )

        holder_did = DIDKey.from_public_key_b58(
            self.holder_key_info.verkey, KeyType.ED25519
        )
        holder_verification_method = holder_did.key_id

        holder_suite = Ed25519Signature2018(
            verification_method=holder_verification_method,
            key_pair=Ed25519WalletKeyPair(
                wallet=self.wallet, public_key_base58=self.holder_key_info.verkey
            ),
            date=datetime.strptime("2021-12-11T03:50:55Z", "%Y-%m-%dT%H:%M:%SZ"),
        )

        credential_template = CREDENTIAL_TEMPLATE.copy()
        credential_template["credentialSubject"]["id"] = holder_did.did

        issued = await issue(
            credential=credential_template,
            suite=issuer_suite,
            document_loader=custom_document_loader,
        )

        unsigned_presentation = await create_presentation(credentials=[issued])

        presentation = await sign_presentation(
            presentation=unsigned_presentation,
            suite=holder_suite,
            document_loader=custom_document_loader,
            challenge=self.presentation_challenge,
        )

    async def test_verify_presentation(self):
        # TODO: verify with multiple suites
        suite = Ed25519Signature2018(
            key_pair=Ed25519WalletKeyPair(wallet=self.wallet),
        )
        verification_result = await verify_presentation(
            presentation=PRESENTATION_SIGNED,
            challenge=self.presentation_challenge,
            suites=[suite],
            document_loader=custom_document_loader,
        )

        # TODO match against stored verification result for continuity
        assert verification_result.verified == True

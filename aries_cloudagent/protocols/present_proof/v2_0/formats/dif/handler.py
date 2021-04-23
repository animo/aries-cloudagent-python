"""V2.0 present-proof dif presentation-exchange format handler."""

import logging

from marshmallow import RAISE
import json
from typing import Mapping, Tuple
import asyncio
import time

from ......cache.base import BaseCache
from ......did.did_key import DIDKey
from ......ledger.base import BaseLedger
from ......messaging.decorators.attach_decorator import AttachDecorator
from ......storage.base import BaseStorage
from ......storage.error import StorageNotFoundError
from ......storage.vc_holder.base import VCHolder
from ......wallet.base import BaseWallet, DIDInfo
from ......wallet.key_type import KeyType

from ...message_types import (
    ATTACHMENT_FORMAT,
    PRES_20_REQUEST,
    PRES_20,
    PRES_20_PROPOSAL,
    PRES_20_ACK,
)
from ....dif.proof_request import DIFProofRequestSchema
from ....dif.pres_exch_handler import (
    create_vp
)
from ....dif.pres_exch import (
    VerifiablePresentation,
    VerifiablePresentationSchema,
    InputDescriptorsSchema,
)
from ......vc.ld_proofs import (
    Ed25519Signature2018,
    BbsBlsSignature2020,
    BbsBlsSignatureProof2020,
    WalletKeyPair,
    LinkedDataProof,
    CredentialIssuancePurpose,
    ProofPurpose,
    DocumentLoader,
    AuthenticationProofPurpose,
)

from ...messages.pres_ack import V20PresAck
from ...messages.pres_format import V20PresFormat
from ...messages.pres_proposal import V20PresProposal
from ...messages.pres_request import V20PresRequest
from ...messages.pres import V20Pres
from ...models.pres_exchange import V20PresExRecord
from ..handler import V20PresFormatHandler, V20PresFormatError

LOGGER = logging.getLogger(__name__)


class IndyPresExchangeHandler(V20PresFormatHandler):
    """DIF presentation format handler."""

    format = V20PresFormat.Format.DIF

    SIGNATURE_SUITE_KEY_TYPE_MAPPING = {
        Ed25519Signature2018: KeyType.ED25519,
        BbsBlsSignature2020: KeyType.BLS12381G2,
        BbsBlsSignatureProof2020: KeyType.BLS12381G2,
    }
    PROOF_TYPE_SIGNATURE_SUITE_MAPPING = {
        suite.signature_type: suite
        for suite, key_type in SIGNATURE_SUITE_KEY_TYPE_MAPPING.items()
    }

    async def _get_issue_suite(
        self,
        *,
        proof_type: str,
        wallet: BaseWallet,
        issuer_id: str,
    ):
        """Get signature suite for signing presentation."""
        did_info = await self._did_info_for_did(issuer_id)
        verification_method = self._get_verification_method(issuer_id)

        # Get signature class based on proof type
        SignatureClass = PROOF_TYPE_SIGNATURE_SUITE_MAPPING[proof_type]

        # Generically create signature class
        return SignatureClass(
            verification_method=verification_method,
            key_pair=WalletKeyPair(
                wallet=wallet,
                key_type=SIGNATURE_SUITE_KEY_TYPE_MAPPING[SignatureClass],
                public_key_base58=did_info.verkey if did_info else None,
            ),
        )

    async def _get_derive_suite(
        self,
        *,
        proof_type: str,
        wallet: BaseWallet,
        issuer_id: str,
    ):
        """Get signature suite for deriving credentials."""
        did_info = await self._did_info_for_did(issuer_id)

        # Get signature class based on proof type
        SignatureClass = PROOF_TYPE_SIGNATURE_SUITE_MAPPING[proof_type]

        # Generically create signature class
        return SignatureClass(
            key_pair=WalletKeyPair(
                wallet=wallet,
                key_type=SIGNATURE_SUITE_KEY_TYPE_MAPPING[SignatureClass],
                public_key_base58=did_info.verkey if did_info else None,
            ),
        )

    def _get_verification_method(self, did: str):
        """Get the verification method for a did."""

        if did.startswith("did:key:"):
            return DIDKey.from_did(did).key_id
        elif did.startswith("did:sov:"):
            # key-1 is what uniresolver uses for key id
            return did + "#key-1"
        else:
            raise V20PresFormatError(
                f"Unable to get retrieve verification method for did {did}"
    )

    async def _did_info_for_did(self, did: str) -> DIDInfo:
        """Get the did info for specified did.

        If the did starts with did:sov it will remove the prefix for
        backwards compatibility with not fully qualified did.

        Args:
            did (str): The did to retrieve from the wallet.

        Raises:
            WalletNotFoundError: If the did is not found in the wallet.

        Returns:
            DIDInfo: did information

        """
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)

            # If the did starts with did:sov we need to query without
            if did.startswith("did:sov:"):
                return await wallet.get_local_did(did.replace("did:sov:", ""))

            # All other methods we can just query
            return await wallet.get_local_did(did)

    @classmethod
    def validate_fields(cls, message_type: str, attachment_data: Mapping):
        """Validate attachment data for a specific message type.

        Uses marshmallow schemas to validate if format specific attachment data
        is valid for the specified message type. Only does structural and type
        checks, does not validate if .e.g. the issuer value is valid.


        Args:
            message_type (str): The message type to validate the attachment data for.
                Should be one of the message types as defined in message_types.py
            attachment_data (Mapping): [description]
                The attachment data to valide

        Raises:
            Exception: When the data is not valid.

        """
        mapping = {
            PRES_20_REQUEST: DIFProofRequestSchema,
            PRES_20_PROPOSAL: InputDescriptorsSchema,
            PRES_20: VerifiablePresentationSchema,
        }

        # Get schema class
        Schema = mapping[message_type]

        # Validate, throw if not valid
        Schema(unknown=RAISE).load(attachment_data)

    def get_format_data(self, message_type: str, data: dict) -> PresFormatAttachment:
        """Get presentation format and attachment objects for use in presentation ex messages.

        Returns a tuple of both presentation format and attachment decorator for use
        in presentation exchange messages. It looks up the correct format identifier and
        encodes the data as a base64 attachment.

        Args:
            message_type (str): The message type for which to return the cred format.
                Should be one of the message types defined in the message types file
            data (dict): The data to include in the attach decorator

        Returns:
            PresFormatAttachment: Presentation format and attachment data objects

        """
        return (
            V20PresFormat(
                attach_id=format.api,
                format_=ATTACHMENT_FORMAT[message_type][format.api],
            ),
            AttachDecorator.data_json(data, ident=format.api),
        )
    
    async def create_exchange_for_proposal(
        self,
        pres_ex_record: V20PresExRecord,
        pres_proposal_message: V20PresProposal,
    ) -> None:
        """Create a presentation exchange record for input presentation proposal."""

    async def receive_pres_proposal(
        self,
        pres_ex_record: V20PresExRecord,
        message: V20PresProposal,
    ) -> None:
        """Receive a presentation proposal from message in context on manager creation."""

    async def create_exchange_for_request(
        self,
        pres_ex_record: V20PresExRecord,
        pres_request_message: V20PresRequest,
    ) -> None:
        """Create a presentation exchange record for input presentation request."""

    async def create_bound_request(
        self,
        pres_ex_record: V20PresExRecord,
        name: str = None,
        version: str = None,
        nonce: str = None,
        comment: str = None,
    ) -> Tuple[V20PresFormat, AttachDecorator]:
        """
        Create a presentation request bound to a proposal.

        Args:
            pres_ex_record: Presentation exchange record for which
                to create presentation request
            name: name to use in presentation request (None for default)
            version: version to use in presentation request (None for default)
            nonce: nonce to use in presentation request (None to generate)
            comment: Optional human-readable comment pertaining to request creation

        Returns:
            A tuple (updated presentation exchange record, presentation request message)

        """
        dif_proof_request = V20PresProposal.deserialize(
            pres_ex_record.pres_proposal
        ).attachment(format)

        return self.get_format_data(PRES_20_REQUEST, dif_proof_request)

    async def create_pres(
        self,
        pres_ex_record: V20PresExRecord,
        requested_credentials: dict,
        comment: str = None,
    ) -> Tuple[V20PresFormat, AttachDecorator]:
        """Create a presentation."""
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            issuer_id = await wallet.get_public_did()
            proof_request = V20PresRequest.deserialize(
                pres_ex_record.pres_request
            ).attachment(format)
            try:    
                holder = self.profile.session.inject(VCHolder)
                # Get all stored credentials
                search = holder.search_credentials()
                # Defaults to page_size but would like to include all
                records = await search.fetch()
            except StorageNotFoundError as err:
                raise V20PresFormatError(err)
            challenge = proof_request.get("challenge") or None
            domain = proof_request.get("domain") or None
            pres_definition = proof_request.get("presentation_definitions")
            pres = create_vp(
                challenge=challenge,
                domain=domain,
                pd=pres_definition,
                profile=self.profile,
                credentials=records,

            )


    async def receive_pres(
        self, message: V20Pres, pres_ex_record: V20PresExRecord
    ) -> None:
        """Receive a presentation, from message in context on manager creation"""


    async def verify_pres(self, pres_ex_record: V20PresExRecord) -> V20PresExRecord:
        """
        Verify a presentation.

        Args:
            pres_ex_record: presentation exchange record
                with presentation request and presentation to verify

        Returns:
            presentation exchange record, updated

        """

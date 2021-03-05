"""V2.0 issue-credential protocol manager."""

import logging

from typing import Mapping, Tuple

from ....core.error import BaseError
from ....core.profile import Profile
from ....storage.error import StorageNotFoundError

from .messages.cred_ack import V20CredAck
from .messages.cred_format import V20CredFormat
from .messages.cred_issue import V20CredIssue
from .messages.cred_offer import V20CredOffer
from .messages.cred_proposal import V20CredProposal
from .messages.cred_request import V20CredRequest
from .messages.inner.cred_preview import V20CredPreview
from .models.cred_ex_record import V20CredExRecord

LOGGER = logging.getLogger(__name__)


class V20CredManagerError(BaseError):
    """Credential manager error under issue-credential protocol v2.0."""


class V20CredManager:
    """Class for managing credentials."""

    def __init__(self, profile: Profile):
        """
        Initialize a V20CredManager.

        Args:
            profile: The profile instance for this credential manager
        """
        self._profile = profile

    @property
    def profile(self) -> Profile:
        """
        Accessor for the current profile instance.

        Returns:
            The profile instance for this credential manager

        """
        return self._profile

    async def prepare_send(
        self,
        conn_id: str,
        cred_proposal: V20CredProposal,
        auto_remove: bool = None,
    ) -> Tuple[V20CredExRecord, V20CredOffer]:
        """
        Set up a new credential exchange record for an automated send.

        Args:
            conn_id: connection for which to create offer
            cred_proposal: credential proposal with preview
            auto_remove: flag to remove the record automatically on completion

        Returns:
            A tuple of the new credential exchange record and credential offer message

        """
        if auto_remove is None:
            auto_remove = not self._profile.settings.get("preserve_exchange_records")
        cred_ex_record = V20CredExRecord(
            conn_id=conn_id,
            initiator=V20CredExRecord.INITIATOR_SELF,
            role=V20CredExRecord.ROLE_ISSUER,
            cred_proposal=cred_proposal.serialize(),
            auto_issue=True,
            auto_remove=auto_remove,
            trace=(cred_proposal._trace is not None),
        )
        (cred_ex_record, cred_offer) = await self.create_offer(
            cred_ex_record=cred_ex_record,
            comment="create automated v2.0 credential exchange record",
        )
        return (cred_ex_record, cred_offer)

    async def create_proposal(
        self,
        conn_id: str,
        *,
        auto_remove: bool = None,
        comment: str = None,
        cred_preview: V20CredPreview,
        fmt2filter: Mapping[V20CredFormat.Format, Mapping[str, str]],
        trace: bool = False,
    ) -> V20CredExRecord:
        """
        Create a credential proposal.

        Args:
            conn_id: connection for which to create proposal
            auto_remove: whether to remove record automatically on completion
            comment: optional human-readable comment to include in proposal
            cred_preview: credential preview to use to create credential proposal
            fmt2filter: mapping between format and filter
            trace: whether to trace the operation

        Returns:
            Resulting credential exchange record including credential proposal

        """

        if auto_remove is None:
            auto_remove = not self._profile.settings.get("preserve_exchange_records")
        cred_ex_record = V20CredExRecord(
            conn_id=conn_id,
            # thread_id=cred_proposal_message._thread_id,
            initiator=V20CredExRecord.INITIATOR_SELF,
            role=V20CredExRecord.ROLE_HOLDER,
            state=V20CredExRecord.STATE_PROPOSAL_SENT,
            # cred_proposal=cred_proposal_message.serialize(),
            auto_remove=auto_remove,
            trace=trace,
        )

        # Format specific create_proposal handler
        formats = [
            await fmt.handler(self._profile).create_proposal(cred_ex_record, filter)
            for (fmt, filter) in fmt2filter.items()
        ]

        cred_proposal_message = V20CredProposal(
            comment=comment,
            credential_preview=cred_preview,
            formats=[format for (format, _) in formats],
            filters_attach=[attach for (_, attach) in formats],
        )
        cred_proposal_message.assign_trace_decorator(self._profile.settings, trace)

        async with self._profile.session() as session:
            await cred_ex_record.save(
                session,
                reason="create v2.0 credential proposal",
            )
        return cred_ex_record

    async def receive_proposal(
        self,
        cred_proposal_message: V20CredProposal,
        conn_id: str,
    ) -> V20CredExRecord:
        """
        Receive a credential proposal.

        Returns:
            The resulting credential exchange record, created

        """
        # at this point, cred def and schema still open to potential negotiation
        cred_ex_record = V20CredExRecord(
            conn_id=conn_id,
            thread_id=cred_proposal_message._thread_id,
            initiator=V20CredExRecord.INITIATOR_EXTERNAL,
            role=V20CredExRecord.ROLE_ISSUER,
            state=V20CredExRecord.STATE_PROPOSAL_RECEIVED,
            cred_proposal=cred_proposal_message.serialize(),
            auto_offer=self._profile.settings.get(
                "debug.auto_respond_credential_proposal"
            ),
            auto_issue=self._profile.settings.get(
                "debug.auto_respond_credential_request"
            ),
            auto_remove=not self._profile.settings.get("preserve_exchange_records"),
            trace=(cred_proposal_message._trace is not None),
        )
        async with self._profile.session() as session:
            await cred_ex_record.save(
                session,
                reason="receive v2.0 credential proposal",
            )

        return cred_ex_record

    async def create_offer(
        self,
        cred_ex_record: V20CredExRecord,
        replacement_id: str = None,
        comment: str = None,
    ) -> Tuple[V20CredExRecord, V20CredOffer]:
        """
        Create credential offer, update credential exchange record.

        Args:
            cred_ex_record: credential exchange record for which to create offer
            replacement_id: identifier to help coordinate credential replacement
            comment: optional human-readable comment to set in offer message

        Returns:
            A tuple (credential exchange record, credential offer message)

        """

        cred_proposal_message = V20CredProposal.deserialize(
            cred_ex_record.cred_proposal
        )
        cred_proposal_message.assign_trace_decorator(
            self._profile.settings, cred_ex_record.trace
        )

        # Format specific create_offer handler
        formats = [
            await V20CredFormat.Format.get(p.format)
            .handler(self.profile)
            .create_offer(cred_ex_record)
            for p in cred_proposal_message.formats
        ]

        cred_offer_message = V20CredOffer(
            replacement_id=replacement_id,
            comment=comment,
            credential_preview=cred_proposal_message.credential_preview,
            formats=[format for (format, _) in formats],
            offers_attach=[attach for (_, attach) in formats],
        )

        cred_offer_message._thread = {"thid": cred_ex_record.thread_id}
        cred_offer_message.assign_trace_decorator(
            self._profile.settings, cred_ex_record.trace
        )

        cred_ex_record.thread_id = cred_offer_message._thread_id
        cred_ex_record.state = V20CredExRecord.STATE_OFFER_SENT
        cred_ex_record.cred_offer = cred_offer_message.serialize()

        async with self._profile.session() as session:
            await cred_ex_record.save(session, reason="create v2.0 credential offer")

        return (cred_ex_record, cred_offer_message)

    async def receive_offer(
        self,
        cred_offer_message: V20CredOffer,
        conn_id: str,
    ) -> V20CredExRecord:
        """
        Receive a credential offer.

        Args:
            cred_offer_message: credential offer message
            conn_id: connection identifier

        Returns:
            The credential exchange record, updated

        """

        # TODO: assert for all methods that we support at least one format
        # TODO: assert we don't suddenly change from format during the interaction

        async with self._profile.session() as session:
            # Get credential exchange record (holder sent proposal first)
            # or create it (issuer sent offer first)
            try:
                cred_ex_record = await (
                    V20CredExRecord.retrieve_by_conn_and_thread(
                        session, conn_id, cred_offer_message._thread_id
                    )
                )
            except StorageNotFoundError:  # issuer sent this offer free of any proposal
                cred_ex_record = V20CredExRecord(
                    conn_id=conn_id,
                    thread_id=cred_offer_message._thread_id,
                    initiator=V20CredExRecord.INITIATOR_EXTERNAL,
                    role=V20CredExRecord.ROLE_HOLDER,
                    auto_remove=not self._profile.settings.get(
                        "preserve_exchange_records"
                    ),
                    trace=(cred_offer_message._trace is not None),
                )

            # Format specific receive_offer handler
            for cred_format in cred_offer_message.formats:
                await V20CredFormat.Format.get(cred_format.format).handler(
                    self.profile
                ).receive_offer(cred_ex_record, cred_offer_message)

            cred_ex_record.cred_offer = cred_offer_message.serialize()
            cred_ex_record.state = V20CredExRecord.STATE_OFFER_RECEIVED

            await cred_ex_record.save(session, reason="receive v2.0 credential offer")

        return cred_ex_record

    async def create_request(
        self, cred_ex_record: V20CredExRecord, holder_did: str, comment: str = None
    ) -> Tuple[V20CredExRecord, V20CredRequest]:
        """
        Create a credential request.

        Args:
            cred_ex_record: credential exchange record for which to create request
            holder_did: holder DID
            comment: optional human-readable comment to set in request message

        Returns:
            A tuple (credential exchange record, credential request message)

        """
        # react to credential offer
        if cred_ex_record.state:
            if cred_ex_record.state != V20CredExRecord.STATE_OFFER_RECEIVED:
                raise V20CredManagerError(
                    f"Credential exchange {cred_ex_record.cred_ex_id} "
                    f"in {cred_ex_record.state} state "
                    f"(must be {V20CredExRecord.STATE_OFFER_RECEIVED})"
                )

            cred_offer = V20CredOffer.deserialize(cred_ex_record.cred_offer)

            formats = cred_offer.formats
        # start with request (not allowed for indy -> checked in indy format handler)
        else:
            # TODO: where to get data from if starting from request. proposal?
            cred_proposal = V20CredOffer.deserialize(cred_ex_record.cred_proposal)
            formats = cred_proposal.formats

        # Format specific create_request handler
        request_formats = [
            await V20CredFormat.Format.get(p.format).handler(self.profile)
            # TODO: retrieve holder did from create_request handler?
            .create_request(cred_ex_record, holder_did)
            for p in formats
        ]

        cred_request_message = V20CredRequest(
            comment=comment,
            formats=[format for (format, _) in request_formats],
            requests_attach=[attach for (_, attach) in request_formats],
        )

        cred_request_message._thread = {"thid": cred_ex_record.thread_id}
        cred_request_message.assign_trace_decorator(
            self._profile.settings, cred_ex_record.trace
        )

        cred_ex_record.thread_id = cred_request_message._thread_id
        cred_ex_record.state = V20CredExRecord.STATE_REQUEST_SENT
        cred_ex_record.cred_request = cred_request_message.serialize()

        async with self._profile.session() as session:
            await cred_ex_record.save(session, reason="create v2.0 credential request")

        return (cred_ex_record, cred_request_message)

    async def receive_request(
        self, cred_request_message: V20CredRequest, conn_id: str
    ) -> V20CredExRecord:
        """
        Receive a credential request.

        Args:
            cred_request_message: credential request to receive
            conn_id: connection identifier

        Returns:
            credential exchange record, updated

        """
        async with self._profile.session() as session:
            try:
                cred_ex_record = await (
                    V20CredExRecord.retrieve_by_conn_and_thread(
                        session, conn_id, cred_request_message._thread_id
                    )
                )
            except StorageNotFoundError:  # holder sent this request free of any offer
                cred_ex_record = V20CredExRecord(
                    conn_id=conn_id,
                    thread_id=cred_request_message._thread_id,
                    initiator=V20CredExRecord.INITIATOR_EXTERNAL,
                    role=V20CredExRecord.ROLE_ISSUER,
                    auto_remove=not self._profile.settings.get(
                        "preserve_exchange_records"
                    ),
                    trace=(cred_request_message._trace is not None),
                )

            for cred_format in cred_request_message.formats:
                await V20CredFormat.Format.get(cred_format.format).handler(
                    self.profile
                ).receive_request(cred_ex_record, cred_request_message)

            cred_ex_record.cred_request = cred_request_message.serialize()
            cred_ex_record.state = V20CredExRecord.STATE_REQUEST_RECEIVED

            await cred_ex_record.save(session, reason="receive v2.0 credential request")

        return cred_ex_record

    async def issue_credential(
        self,
        cred_ex_record: V20CredExRecord,
        *,
        comment: str = None,
    ) -> Tuple[V20CredExRecord, V20CredIssue]:
        """
        Issue a credential.

        Args:
            cred_ex_record: credential exchange record for which to issue credential
            comment: optional human-readable comment pertaining to credential issue

        Returns:
            Tuple: (Updated credential exchange record, credential issue message)

        """

        if cred_ex_record.state != V20CredExRecord.STATE_REQUEST_RECEIVED:
            raise V20CredManagerError(
                f"Credential exchange {cred_ex_record.cred_ex_id} "
                f"in {cred_ex_record.state} state "
                f"(must be {V20CredExRecord.STATE_REQUEST_RECEIVED})"
            )

        if cred_ex_record.cred_issue:
            raise V20CredManagerError(
                "issue_credential() called multiple times for "
                f"cred ex record {cred_ex_record.cred_ex_id}"
            )

        # TODO: replacement id for jsonld start from request
        replacement_id = None
        formats = V20CredRequest.deserialize(cred_ex_record.cred_request).formats

        if cred_ex_record.cred_offer:
            cred_offer_message = V20CredOffer.deserialize(cred_ex_record.cred_offer)
            replacement_id = cred_offer_message.replacement_id

            # TODO: How do we verify if requests matches offer?
            # Use offer formats if offer is sent
            formats = cred_offer_message.formats

        # Format specific issue_credential handler
        issue_formats = [
            await V20CredFormat.Format.get(p.format)
            .handler(self.profile)
            .issue_credential(cred_ex_record)
            for p in formats
        ]

        cred_issue_message = V20CredIssue(
            replacement_id=replacement_id,
            comment=comment,
            formats=[format for (format, _) in issue_formats],
            credentials_attach=[attach for (_, attach) in issue_formats],
        )

        cred_ex_record.state = V20CredExRecord.STATE_ISSUED
        cred_ex_record.cred_issue = cred_issue_message.serialize()
        async with self._profile.session() as session:
            # FIXME - re-fetch record to check state, apply transactional update
            await cred_ex_record.save(session, reason="v2.0 issue credential")

        cred_issue_message._thread = {"thid": cred_ex_record.thread_id}
        cred_issue_message.assign_trace_decorator(
            self._profile.settings, cred_ex_record.trace
        )

        return (cred_ex_record, cred_issue_message)

    async def receive_credential(
        self, cred_issue_message: V20CredIssue, conn_id: str
    ) -> V20CredExRecord:
        """
        Receive a credential issue message from an issuer.

        Hold cred in storage potentially to be processed by controller before storing.

        Returns:
            Credential exchange record, retrieved and updated

        """
        assert cred_issue_message.credentials_attach

        # FIXME use transaction, fetch for_update
        async with self._profile.session() as session:
            cred_ex_record = await (
                V20CredExRecord.retrieve_by_conn_and_thread(
                    session,
                    conn_id,
                    cred_issue_message._thread_id,
                )
            )

            cred_ex_record.cred_issue = cred_issue_message.serialize()
            cred_ex_record.state = V20CredExRecord.STATE_CREDENTIAL_RECEIVED

            await cred_ex_record.save(session, reason="receive v2.0 credential issue")
        return cred_ex_record

    async def store_credential(
        self, cred_ex_record: V20CredExRecord, cred_id: str = None
    ) -> Tuple[V20CredExRecord, V20CredAck]:
        """
        Store a credential in holder wallet; send ack to issuer.

        Args:
            cred_ex_record: credential exchange record with credential to store and ack
            cred_id: optional credential identifier to override default on storage

        Returns:
            Tuple: (Updated credential exchange record, credential ack message)

        """
        if cred_ex_record.state != (V20CredExRecord.STATE_CREDENTIAL_RECEIVED):
            raise V20CredManagerError(
                f"Credential exchange {cred_ex_record.cred_ex_id} "
                f"in {cred_ex_record.state} state "
                f"(must be {V20CredExRecord.STATE_CREDENTIAL_RECEIVED})"
            )

        # Format specific store_credential handler
        for cred_format in V20CredIssue.deserialize(cred_ex_record.cred_issue).formats:
            await V20CredFormat.Format.get(cred_format.format).handler(
                self.profile
            ).store_credential(cred_ex_record, cred_id)

        cred_ex_record.state = V20CredExRecord.STATE_DONE

        async with self._profile.session() as session:
            # FIXME - re-fetch record to check state, apply transactional update
            await cred_ex_record.save(session, reason="store credential v2.0")

        cred_ack_message = V20CredAck()
        cred_ack_message.assign_thread_id(
            cred_ex_record.thread_id, cred_ex_record.parent_thread_id
        )
        cred_ack_message.assign_trace_decorator(
            self._profile.settings, cred_ex_record.trace
        )

        if cred_ex_record.auto_remove:
            await self.delete_cred_ex_record(cred_ex_record.cred_ex_id)

        return (cred_ex_record, cred_ack_message)

    async def receive_credential_ack(
        self, cred_ack_message: V20CredAck, conn_id: str
    ) -> V20CredExRecord:
        """
        Receive credential ack from holder.

        Args:
            cred_ack_message: credential ack message to receive
            conn_id: connection identifier

        Returns:
            credential exchange record, retrieved and updated

        """
        # FIXME use transaction, fetch for_update
        async with self._profile.session() as session:
            cred_ex_record = await (
                V20CredExRecord.retrieve_by_conn_and_thread(
                    session,
                    conn_id,
                    cred_ack_message._thread_id,
                )
            )

            cred_ex_record.state = V20CredExRecord.STATE_DONE
            await cred_ex_record.save(session, reason="receive credential ack v2.0")

        if cred_ex_record.auto_remove:
            await self.delete_cred_ex_record(cred_ex_record.cred_ex_id)

        return cred_ex_record

    async def delete_cred_ex_record(self, cred_ex_id: str) -> None:
        """Delete credential exchange record and associated detail records."""

        async with self._profile.session() as session:
            for fmt in V20CredFormat.Format:  # details first: do not strand any orphans
                try:
                    detail_record = await fmt.detail.retrieve_by_cred_ex_id(
                        session,
                        cred_ex_id,
                    )
                    await detail_record.delete_record(session)
                except StorageNotFoundError:
                    pass

            cred_ex_record = await V20CredExRecord.retrieve_by_id(session, cred_ex_id)
            await cred_ex_record.delete_record(session)

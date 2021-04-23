"""A (proof) presentation content message."""

from typing import Sequence

from marshmallow import EXCLUDE, fields, RAISE, validates_schema, ValidationError

from .....messaging.agent_message import AgentMessage, AgentMessageSchema
from .....messaging.decorators.attach_decorator import (
    AttachDecorator,
    AttachDecoratorSchema,
)

from ...indy.proof import IndyProofSchema

from ..message_types import PRES_20, PROTOCOL_PACKAGE

from .pres_format import V20PresFormat, V20PresFormatSchema

HANDLER_CLASS = f"{PROTOCOL_PACKAGE}.handlers.pres_handler.V20PresHandler"


class V20Pres(AgentMessage):
    """Class representing a presentation."""

    class Meta:
        """Presentation metadata."""

        handler_class = HANDLER_CLASS
        schema_class = "V20PresSchema"
        message_type = PRES_20

    def __init__(
        self,
        _id: str = None,
        *,
        comment: str = None,
        formats: Sequence[V20PresFormat] = None,
        presentations_attach: Sequence[AttachDecorator] = None,
        **kwargs,
    ):
        """
        Initialize presentation object.

        Args:
            presentations_attach: attachments
            comment: optional comment

        """
        super().__init__(_id=_id, **kwargs)
        self.comment = comment
        self.formats = formats if formats else []
        self.presentations_attach = (
            list(presentations_attach) if presentations_attach else []
        )

    def attachment(self, fmt: V20PresFormat.Format = None) -> dict:
        """
        Return attached presentation item.

        Args:
            fmt: format of attachment in list to decode and return

        """
        return (
            (
                fmt or V20PresFormat.Format.get(self.formats[0].format)
            ).get_attachment_data(self.formats, self.presentations_attach)
            if self.formats
            else None
        )


class V20PresSchema(AgentMessageSchema):
    """Presentation schema."""

    class Meta:
        """Presentation schema metadata."""

        model_class = V20Pres
        unknown = EXCLUDE

    comment = fields.Str(
        description="Human-readable comment", required=False, allow_none=True
    )
    formats = fields.Nested(
        V20PresFormatSchema,
        many=True,
        required=True,
        description="Acceptable attachment formats",
    )
    presentations_attach = fields.Nested(
        AttachDecoratorSchema, required=True, many=True, data_key="presentations~attach"
    )

    @validates_schema
    def validate_fields(self, data, **kwargs):
        """Validate presentation attachment per format."""

        def get_attach_by_id(attach_id):
            """Return attachment with input attachment identifier."""
            for atch in attachments:
                if atch.ident == attach_id:
                    return atch
            raise ValidationError(f"No attachment for attach_id {attach_id} in formats")

        formats = data.get("formats") or []
        attachments = data.get("presentations_attach") or []
        if len(formats) != len(attachments):
            raise ValidationError("Formats/attachments length mismatch")

        for fmt in formats:
            atch = get_attach_by_id(fmt.attach_id)
            V20PresFormat.Format.get(fmt.format).validate_fields(
                PRES_20, atch.content
            )

from typing import Union, List


class VerificationException(Exception):
    """Raised when verification verification fails."""

    def __init__(self, message: str, errors: Union[Exception, List[Exception]]):
        self.errors = errors if isinstance(errors, List) else [errors]
        super().__init__(self.message)

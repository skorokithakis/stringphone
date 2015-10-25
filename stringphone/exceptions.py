class BadSignatureError(Exception):
    "Raised when a signature did not verify."
    pass


class IntroductionError(Exception):
    "Raised when a message is an introduction."
    pass


class IntroductionReplyError(Exception):
    "Raised when a message is an introduction reply."
    pass


class UntrustedKeyError(Exception):
    "Raised when the verification key for a signed message could not be found."
    pass

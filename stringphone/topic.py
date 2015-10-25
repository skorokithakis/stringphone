from .crypto import AsymmetricCrypto, Signer, SymmetricCrypto, Verifier
from .exceptions import IntroductionError, IntroductionReplyError, UntrustedKeyError


def get_id_from_key(key):
    return key[:16]


class Topic:
    """
    A topic is the main avenue of communication. It can be any one-to-many
    channel, such as an MQTT topic, an IRC chat room, or even a TCP socket
    (one-to-one is a subset of one-to-many communication).
    """

    def __init__(self, signing_key, topic_key=None, participants=None):
        if participants is None:
            participants = {}
        self._participants = participants

        self._init_symmetric_crypto(topic_key)
        self._signer = Signer(signing_key)
        self._asymmetric_crypto = AsymmetricCrypto()

    def _init_symmetric_crypto(self, topic_key):
        """
        Initialize the symmetric crypto with either the topic key, if known, or
        None if unknown. If we don't know the topic key yet, we must perform an
        introduction and hope one of the other participants sends it to us.
        """
        self._topic_key = topic_key
        if topic_key is None:
            # We don't have the topic key yet, we're going to introduce
            # ourselves to other devices hoping to get a key back.
            self._symmetric_crypto = None
        else:
            self._symmetric_crypto = SymmetricCrypto(topic_key)

    #########
    # Participant methods
    #
    def add_participant(self, public_key):
        "Add a participant to the list of trusted participants."
        self._participants[get_id_from_key(public_key)] = public_key

    def remove_participant(self, participant_id):
        "Remove a participant from the list of trusted participants."
        del self._participants[participant_id]

    def participants(self):
        "Return all trusted participants."
        return self._participants

    #########
    # Introduction methods
    #
    def _unpack_introduction(self, message):
        """
        Unpack the signing key and encryption key of the participant that is
        introducing itself from the message.
        """
        signing_key = None
        encryption_key = None
        encrypted_topic_key = None

        if message.startswith(b"i"):
            signing_key = message[1:33]
            encryption_key = message[33:]
        elif message.startswith(b"r"):
            encrypted_topic_key = message[1:73]
            encryption_key = message[73:105]
            signing_key = message[105:]

        data = {}
        if signing_key:
            data["participant_id"] = get_id_from_key(signing_key)
            data["signing_key"] = signing_key

        if encryption_key:
            data["encryption_key"] = encryption_key

        if encrypted_topic_key:
            data["encrypted_topic_key"] = encrypted_topic_key

        return data

    def construct_introduction(self):
        "Generate an introduction of ourselves to send to other devices."
        return b"i" + self._signer.public_key + self._asymmetric_crypto.public_key

    def get_discovery_info(self, message):
        """
        Return the participant information from the given introduction or
        introduction reply so we can add the participant to our trusted
        participants.

        Accepts the raw introduction message from the channel and returns the
        participant's ID and their public key.
        """
        data = self._unpack_introduction(message)
        return {
            "participant_id": data["participant_id"],
            "participant_key": data["signing_key"]
        }

    def construct_introduction_reply(self, message):
        """
        Generate a reply to an introduction. This gives the party that was just
        introduced FULL ACCESS to the topic's key and all decrypted messages.
        """
        if self._topic_key is None:
            raise RuntimeError(
                "Cannot construct introduction reply, topic key is unknown.")
        # The public key of the participant requesting the topic key.
        data = self._unpack_introduction(message)
        encrypted_topic_key = self._asymmetric_crypto.encrypt(
            self._topic_key, data["encryption_key"])
        return b"r" + encrypted_topic_key + self._asymmetric_crypto.public_key + self._signer.public_key

    def decode_introduction_reply(self, message):
        data = self._unpack_introduction(message)
        topic_key = self._asymmetric_crypto.decrypt(data["encrypted_topic_key"],
                                                    data["encryption_key"])
        self._init_symmetric_crypto(topic_key)

    #########
    # Encoding/decoding methods
    #
    def encode(self, message):
        """
        Encode a message from transmission. The message must be a bytestring.

        Returns a bytestring of the encrypted ciphertext.
        """
        ciphertext = self.id + self._symmetric_crypto.encrypt(
            message
        )
        signed = self._signer.sign(ciphertext)
        return b"m" + signed

    def decode(self, message, naive=False):
        """
        Decode a message. The message must be a bytestring.

        If `naive` is True, signature verification will not be performed. Use
        at your own risk.

        Returns a bytestring of the decrypted and (optionally) verified plaintext.
        """
        if message.startswith(b"i") and self._topic_key:
            # This is an introduction.
            raise IntroductionError("The received message is an introduction.")
        elif message.startswith(b"r") and self._topic_key is None:
            # This is a reply to an introduction.
            raise IntroductionReplyError(
                "The received message is an introduction.")
        elif message.startswith(b"m"):
            message = message[1:]
            # Split the message envelope (signature, participant_id, ciphertext)
            # into two of its constituent parts.
            participant_id, ciphertext = message[64:80], message[80:]
            if not naive:
                # Verify the signature.
                if participant_id not in self._participants:
                    raise UntrustedKeyError(
                        "Verification key for participant not found."
                    )
                participant_key = self._participants[participant_id]
                verifier = Verifier(participant_key)
                verifier.verify(message)
            plaintext = self._symmetric_crypto.decrypt(ciphertext)
            return plaintext

    #########
    # Various
    #
    @property
    def public_key(self):
        return self._signer.public_key

    @property
    def id(self):
        return get_id_from_key(self.public_key)

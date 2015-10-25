"""
Classes and methods relating to the topic and its participants.
"""
from .crypto import AsymmetricCrypto, Signer, SymmetricCrypto, Verifier
from .exceptions import IntroductionError, IntroductionReplyError, UntrustedKeyError


def _get_id_from_key(public_key):
    """
    Derive the participant's ID from the public key.
    """
    return public_key[:16]


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

        :param bytes topic_key: The symmetric key of the topic, or None.
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
        """
        Add a participant to the list of trusted participants.

        :param bytes public_key: The public key of the participant to add.
        """
        self._participants[_get_id_from_key(public_key)] = public_key

    def remove_participant(self, participant_id):
        """
        Remove a participant from the list of trusted participants.

        :param bytes participant_id: The ID of the participant to remove.
        """
        del self._participants[participant_id]

    def participants(self):
        """
        Return all trusted participants.

        :rtype: dict
        """
        return self._participants

    #########
    # Introduction methods
    #
    def _unpack_introduction(self, message):
        """
        Unpack the signing key and encryption key of the participant that is
        introducing itself from the message.

        :param bytes message: The message to unpack.

        :return dict: The unpacked data.
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
            data["participant_id"] = _get_id_from_key(signing_key)
            data["signing_key"] = signing_key

        if encryption_key:
            data["encryption_key"] = encryption_key

        if encrypted_topic_key:
            data["encrypted_topic_key"] = encrypted_topic_key

        return data

    def construct_introduction(self):
        """
        Generate an introduction of ourselves to send to other devices.

        :returns: The message to broadcast.
        :rtype: bytes
        """
        return b"i" + self._signer.public_key + self._asymmetric_crypto.public_key

    def get_discovery_info(self, message):
        """
        Return the participant information from the given introduction or
        introduction reply so we can add the participant to our trusted
        participants.

        :param bytes message: The raw introduction message from the channel and
            returns the participant's ID and their public key.
        :returns: The discovery data.
        :rtype: dict
        """
        data = self._unpack_introduction(message)
        return {
            "participant_id": data["participant_id"],
            "participant_key": data["signing_key"]
        }

    def construct_introduction_reply(self, message):
        """
        Generate a reply to an introduction. This gives the party that was just
        introduced **FULL ACCESS** to the topic key and all decrypted messages.

        :param bytes message: The raw introduction message from the channel.
        :returns: The reply message to broadcast.
        :rtype: bytes
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
        """
        Decode the reply to an introduction. If the reply contains a valid
        encrypted topic key that is addressed to us, add it to the topic.

        :param bytes message: The raw reply message from the channel.
        """
        data = self._unpack_introduction(message)
        topic_key = self._asymmetric_crypto.decrypt(data["encrypted_topic_key"],
                                                    data["encryption_key"])
        self._init_symmetric_crypto(topic_key)

    #########
    # Encoding/decoding methods
    #
    def encode(self, message):
        """
        Encode a message from transmission.

        :param bytes message: The plaintext to encode.

        :returns: The encrypted ciphertext to broadcast.
        :rtype: bytes
        """
        ciphertext = self.id + self._symmetric_crypto.encrypt(message)
        signed = self._signer.sign(ciphertext)
        return b"m" + signed

    def decode(self, message, naive=False, ignore_untrusted=False):
        """
        Decode a message.

        If `naive` is True, signature verification will not be performed. Use
        at your own risk.

        :param bytes message: The plaintext to encode.
        :param bool naive: If `True`, signature verification **IS NOT
            PERFORMED**. Use at your own risk.
        :param bool ignore_untrusted: If `True`, messages from unknown
            participants will be silently ignored. This does not include
            introductions or introduction replies, as those are special and will
            still raise an exception.
        :returns: The decrypted and (optionally) verified plaintext.
        :rtype: bytes
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
                    if ignore_untrusted:
                        # We want to just drop messages from unknown
                        # participants on the floor.
                        return
                    else:
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
        """
        Our public key.

        :rtype: bytes
        """
        return self._signer.public_key

    @property
    def id(self):
        """
        Our ID.

        :rtype: bytes
        """
        return _get_id_from_key(self.public_key)

"""
Classes and methods relating to the topic and its participants.
"""
import hashlib

import nacl.exceptions

from .crypto import AsymmetricCrypto, Signer, SymmetricCrypto, Verifier
from .exceptions import IntroductionError, IntroductionReplyError, MalformedMessageError, MissingTopicKeyError, UntrustedKeyError

PARTICIPANT_ID_LENGTH = 16


def _get_id_from_key(public_key):
    """
    Derive the participant's ID from the public key.

    The ID is the first %s bytes of the SHA256 hash of the participant's public
    key.
    """ % PARTICIPANT_ID_LENGTH
    return hashlib.sha256(public_key).digest()[:PARTICIPANT_ID_LENGTH]


class Topic:
    """
    A topic is the main avenue of communication. It can be any one-to-many
    channel, such as an MQTT topic, an IRC chat room, or even a TCP socket
    (one-to-one is a subset of one-to-many communication).
    """

    def __init__(self, signing_key_seed, topic_key=None, participants=None):
        if participants is None:
            participants = {}
        self._participants = participants

        self._init_symmetric_crypto(topic_key)
        self._signer = Signer(signing_key_seed)
        self._id = _get_id_from_key(self._signer.public_key)
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
    def _unpack_message(self, message):
        """
        Unpack the information contained in the message.

        :param bytes message: The message to unpack.

        :return dict: The unpacked data.
        """
        data = {}

        if message.startswith(b"i"):
            if len(message) != 65:
                raise MalformedMessageError("Malformed message.")
            data["sender_key"] = message[1:33]
            data["encryption_key"] = message[33:]
        elif message.startswith(b"r"):
            if len(message) != 153:
                raise MalformedMessageError("Malformed message.")
            data["recipient_id"] = message[1:17]
            data["encrypted_topic_key"] = message[17:89]
            data["encryption_key"] = message[89:121]
            data["sender_key"] = message[121:]
        elif message.startswith(b"m"):
            if len(message) < 81:
                raise MalformedMessageError("Malformed message.")
            data["sender_id"] = message[65:81]

        if "sender_key" in data and "sender_id" not in data:
            data["sender_id"] = _get_id_from_key(data["sender_key"])

        return data

    def construct_introduction(self):
        """
        Generate an introduction of ourselves to send to other devices.

        :returns: The message to broadcast.
        :rtype: bytes
        """
        return b"i" + self._signer.public_key + self._asymmetric_crypto.public_key

    def get_message_info(self, message):
        """
        Return the participant information from the given introduction or
        introduction reply so we can add the participant to our trusted
        participants.

        :param bytes message: The raw introduction message from the channel and
            returns the participant's ID and their public key.
        :returns: The discovery data.
        :rtype: dict
        """
        return self._unpack_message(message)

    def construct_introduction_reply(self, message):
        """
        Generate a reply to an introduction. This gives the party that was just
        introduced **FULL ACCESS** to the topic key and all decrypted messages.

        :param bytes message: The raw introduction message from the channel.
        :returns: The reply message to broadcast.
        :rtype: bytes
        """
        if not self.has_topic_key:
            raise RuntimeError(
                "Cannot construct introduction reply, topic key is unknown.")
        # The public key of the participant requesting the topic key.
        data = self._unpack_message(message)
        encrypted_topic_key = self._asymmetric_crypto.encrypt(
            self._topic_key, data["encryption_key"])
        return b"r" + data["sender_id"] + encrypted_topic_key + self._asymmetric_crypto.public_key + self._signer.public_key

    def decode_introduction_reply(self, message):
        """
        Decode the reply to an introduction. If the reply contains a valid
        encrypted topic key that is addressed to us, add it to the topic. If we
        already know the topic key, ignore this message.

        :param bytes message: The raw reply message from the channel.
        """
        data = self._unpack_message(message)
        if self.has_topic_key or data["recipient_id"] != self.id:
            # We already know the topic key or the message wasn't for us,
            # disregard.
            return

        topic_key = self._asymmetric_crypto.decrypt(data["encrypted_topic_key"], data["encryption_key"])
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
        if not self.has_topic_key:
            raise MissingTopicKeyError(
                "Cannot encode data without a topic key.")

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
        # Ignore our own messages.
        if self.get_message_info(message).get("sender_id") == self.id:
            return

        if message.startswith(b"i") and self.has_topic_key:
            # This is an introduction.
            raise IntroductionError("The received message is an introduction.")
        elif message.startswith(b"r") and not self.has_topic_key:
            # This is a reply to an introduction.
            raise IntroductionReplyError(
                "The received message is an introduction reply.")
        elif message.startswith(b"m"):
            message = message[1:]
            # Split the message envelope (signature, sender_id, ciphertext)
            # into two of its constituent parts.
            sender_id, ciphertext = message[
                64:64 + PARTICIPANT_ID_LENGTH], message[64 +
                                                        PARTICIPANT_ID_LENGTH:]

            if not naive:
                # Verify the signature.
                if sender_id not in self._participants:
                    if ignore_untrusted:
                        # We want to just drop messages from unknown
                        # participants on the floor.
                        return
                    else:
                        raise UntrustedKeyError(
                            "Verification key for participant not found.")
                sender_key = self._participants[sender_id]
                verifier = Verifier(sender_key)
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
        return self._id

    @property
    def has_topic_key(self):
        """
        Whether we know the topic key and can encrypt and decrypt messages to
        this topic or not.

        :rtype: bool
        """

        return bool(self._topic_key)

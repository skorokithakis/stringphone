"""
lasses and methods relating to the topic and its participants.
"""
from .crypto import (
        PARTICIPANT_ID_LENGTH,
        AsymmetricCrypto,
        Signer,
        SymmetricCrypto,
        Verifier,
        _get_id_from_key,
        generate_signing_key_seed,
    )
from .exceptions import (
        IntroductionError,
        IntroductionReplyError,
        MissingTopicKeyError,
        UntrustedKeyError
    )


MESSAGE_UNKNOWN = b"u"
MESSAGE_SIMPLE = b"s"
MESSAGE_INTRO = b"i"
MESSAGE_REPLY = b"r"


class Message(bytes):
    def __init__(self, message):
        self = message  # noqa

    @property
    def type(self):
        """
        The type of the message.

        :rtype: int
        """
        for message_type in (MESSAGE_SIMPLE, MESSAGE_INTRO, MESSAGE_REPLY):
            if self.startswith(message_type):
                return message_type
        return MESSAGE_UNKNOWN

    @property
    def signed_payload(self):
        """
        The signed payload (signature + ciphertext).

        :rtype: bytes
        :raises ValueError: if the given message type does not have this
            property.
        """
        if self.type != MESSAGE_SIMPLE:
            raise ValueError("Message is of the wrong type for this property.")
        return self[1:]

    @property
    def ciphertext(self):
        """
        The ciphertext.

        :rtype: bytes
        :raises ValueError: if the given message type does not have this
            property.
        """
        if self.type != MESSAGE_SIMPLE:
            raise ValueError("Message is of the wrong type for this property.")
        return self[65 + PARTICIPANT_ID_LENGTH:]

    @property
    def encrypted_topic_key(self):
        """
        The encrypted topic key.

        :rtype: bytes
        :raises ValueError: if the given message type does not have this
            property.
        """
        if self.type == MESSAGE_REPLY:
            return self[17:89]
        else:
            raise ValueError("Message is of the wrong type for this property.")

    @property
    def recipient_id(self):
        """
        The ID of the recipient.

        :rtype: bytes
        :raises ValueError: if the given message type does not have this
            property.
        """
        if self.type == MESSAGE_REPLY:
            return self[1:17]
        else:
            raise ValueError("Message is of the wrong type for this property.")

    @property
    def sender_id(self):
        """
        The ID of the sender.

        :rtype: bytes
        :raises ValueError: if the given message type does not have this
            property.
        """
        if self.type == MESSAGE_SIMPLE:
            return self[65:81]
        elif self.type == MESSAGE_INTRO:
            return _get_id_from_key(self.sender_key)
        elif self.type == MESSAGE_REPLY:
            return _get_id_from_key(self.sender_key)
        else:
            raise ValueError("Message is of the wrong type for this property.")

    @property
    def sender_key(self):
        """
        The public key of the sender.

        :rtype: bytes
        :raises ValueError: if the given message type does not have this
            property.
        """
        if self.type == MESSAGE_SIMPLE:
            return self[65:81]
        elif self.type == MESSAGE_INTRO:
            return self[1:33]
        elif self.type == MESSAGE_REPLY:
            return self[121:153]
        else:
            raise ValueError("Message is of the wrong type for this property.")

    @property
    def encryption_key(self):
        """
        The encryption key that encrypts the topic key.

        :rtype: bytes
        :raises ValueError: if the given message type does not have this
            property.
        """
        if self.type == MESSAGE_INTRO:
            return self[33:]
        elif self.type == MESSAGE_REPLY:
            return self[89:121]
        else:
            raise ValueError("Message is of the wrong type for this property.")


class Topic(object):
    """
    A topic is the main avenue of communication. It can be any one-to-many
    channel, such as an MQTT topic, an IRC chat room, or even a TCP socket
    (one-to-one is a subset of one-to-many communication).
    """

    def __init__(self, signing_key_seed=None, topic_key=None, participants=None):
        """
        Various amounts of state can be passed to initialize according to each
        use case.

        :param bytes signing_key_seed: The optional seed for our signing key.
            If you require identity persistence of this participant across
            restarts, save and provide this. A participant's public and private
            key and ID are generated from this seed, so passing the same seed
            will result in the same keys and ID. **Keep this completely secret
            from everyone**.

            If this is not provided, one will be generated. You will not be able
            to retrieve the generated seed, so only do this if you don't care
            about persistent identities.
        :param bytes topic_key: The optional symmetric encryption key this topic
            uses. If this is known when instantiating, we can start sending and
            receiving messages immediately, and discovery will only be useful to
            get other participants to trust us.

            If this is not provided, encryption and decryption will fail.
        :param dict participants: The optional dictionary of trusted
            participants. This should have the form
            {b"participant_id": b"participant_key"}. Participant keys in this
            dictionary will be trusted when verifying messages signed with them.
        """
        if signing_key_seed is None:
            signing_key_seed = generate_signing_key_seed()

        if participants is None:
            participants = {}

        self._participants = participants
        self._asymmetric_crypto = AsymmetricCrypto()

        self.topic_key = topic_key
        self._signer = Signer(signing_key_seed)
        self._id = _get_id_from_key(self._signer.public_key)

    #########
    # Various properties
    #
    @property
    def id(self):
        """
        Our ID.

        :rtype: bytes
        """
        return self._id

    @property
    def public_key(self):
        """
        Our public key.

        :rtype: bytes
        """
        return self._signer.public_key

    @property
    def topic_key(self):
        """
        Return the topic encryption key.

        :rtype: bytes
        """
        return self._topic_key

    @topic_key.setter
    def topic_key(self, value):
        """
        Initialize the symmetric crypto with either the topic key, if known, or
        None if unknown. If we don't know the topic key yet, we must perform an
        introduction and hope one of the other participants sends it to us.

        :param bytes value: The symmetric key of the topic, or None.
        """
        self._topic_key = value
        if value is None:
            self._symmetric_crypto = None
        else:
            self._symmetric_crypto = SymmetricCrypto(value)

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
    # Discovery methods
    #
    def construct_intro(self):
        """
        Generate an introduction of ourselves to send to other devices.

        :returns: The message to broadcast.
        :rtype: bytes
        """
        return Message(MESSAGE_INTRO + self.public_key +
            self._asymmetric_crypto.public_key)

    def construct_reply(self, message):
        """
        Generate a reply to an introduction. This gives the party that was just
        introduced **FULL ACCESS** to the topic key and all decrypted messages.

        :param bytes message: The raw introduction message from the channel.
        :returns: The reply message to broadcast.
        :rtype: bytes
        """
        if not self.topic_key:
            raise RuntimeError(
                "Cannot construct introduction reply, topic key is unknown.")
        # The public key of the participant requesting the topic key.
        message = Message(message)
        encrypted_topic_key = self._asymmetric_crypto.encrypt(
                self.topic_key,
                message.encryption_key
            )
        return Message(MESSAGE_REPLY + message.sender_id + encrypted_topic_key +
            self._asymmetric_crypto.public_key + self.public_key)

    def parse_reply(self, message):
        """
        Decode the reply to an introduction. If the reply contains a valid
        encrypted topic key that is addressed to us, add it to the topic. If we
        already know the topic key, ignore this message.

        :param bytes message: The raw reply message from the channel.
        :returns: Whether the retrieval of the topic key was successful.
        :rtype: bool
        """
        message = Message(message)
        if self.topic_key or message.recipient_id != self.id:
            # We already know the topic key or the message wasn't for us,
            # disregard.
            return False

        topic_key = self._asymmetric_crypto.decrypt(
            message.encrypted_topic_key,
            message.encryption_key
        )
        self.topic_key = topic_key
        return True

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
        if not self.topic_key:
            raise MissingTopicKeyError(
                "Cannot encode data without a topic key.")

        ciphertext = self.id + self._symmetric_crypto.encrypt(message)
        signed = self._signer.sign(ciphertext)
        return MESSAGE_SIMPLE + signed

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
        message = Message(message)

        # Ignore our own messages.
        if message.sender_id == self.id:
            print("I sent this.")
            return

        if message.type == MESSAGE_INTRO and self.topic_key:
            # This is an introduction.
            raise IntroductionError("The received message is an introduction.")
        elif message.type == MESSAGE_REPLY and not self.topic_key:
            # This is a reply to an introduction.
            raise IntroductionReplyError(
                "The received message is an introduction reply.")
        elif message.type == MESSAGE_SIMPLE:
            if not naive:
                # Verify the signature.
                if message.sender_id not in self._participants:
                    if ignore_untrusted:
                        # We want to just drop messages from unknown
                        # participants on the floor.
                        return
                    else:
                        raise UntrustedKeyError(
                            "Verification key for participant not found.")
                sender_key = self._participants[message.sender_id]
                verifier = Verifier(sender_key)
                verifier.verify(message.signed_payload)
            plaintext = self._symmetric_crypto.decrypt(message.ciphertext)
            return plaintext

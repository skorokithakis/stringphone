String phone
============

    *Nothing is as secure as a string phone.* -- The NSA

Introduction
------------

String phone is a secure communications protocol and library geared towards embedded devices. Its goal is to allow, for
example, your mobile phone to communicate with your home automation devices in a secure manner, even over an insecure
channel. It also allows for authentication of devices, so you can be sure that the only device whose commands will be
accepted is the phone.

String phone isn't a communication layer itself. Rather, it sits over your communication layer, encrypting and signing
messages as required before they are sent over your channel. It also verifies and decrypts incoming messages, ensuring
that devices are who they claim to be, and that no third party can read your communications.

Since complicated things tend to be less secure, string phone aims to have a very simple interface.


Basics
------

(If you are too impatient for theory, skip down to :ref:`getting-started` to... get started)

String phone's communication primitive is a :py:class:`Topic <stringphone.topic.Topic>`. Think of a topic as a room where many devices are shouting at each
other. This can be an MQTT queue, a pub/sub channel, an IRC channel, or even a single socket (one-to-one communication
is a subset of many-to-one).

Each device in the topic is called a *participant*. Each participant has its own, persistent elliptic curve key, that
is kept secret from other participants and anyone else. This key is top secret, and should not be shared with any
person or device. It should never leave the participant's storage. This key is used to identify the participant and
to sign the participant's messages so other participants are sure of who is sending them.

Each topic also has a persistent encryption key, called a *topic key*. The topic key ensures that all communcations
between participants are securely encrypted. The topic key should only be known to the participants. Anyone with the
topic key can read all messages exchanged in the topic without being detected.

.. _getting-started:

Getting started
---------------

We'll start with a simple case. We will create two participants, one called *Alice* and one called *Bob*, both of whom
know the topic key already (they have communicated beforehand over a secure channel and shared the topic key.  Let's
get them to exchange messages securely::

    >>> from stringphone import Topic, generate_signing_key, generate_topic_key

    # Let's generate a topic key to share between the participants.
    #  generate_topic_key() uses a cryptographically secure RNG, so
    # you're safe using it to generate your keys.
    >>> topic_key = generate_topic_key()

    >>> topic_key
    ']j\x9b\xf7\xe77\x07h\xdcF\x82\x95\x0fo\x06\x90\xe1]R\xff\x8a\xeal\xd0\xef\x89J\xbd\x97\xf1[\xb4'

    # Give Alice and Bob one secure signing key each.
    >>> alice = Topic(generate_signing_key(), topic_key)
    >>> bob = Topic(generate_signing_key(), topic_key)

    # Alice encodes a message to send to Bob. This encrypts and signs the message.
    >>> alice_message = alice.encode("Hi Bob!")

    # Bob will try to decode the message.
    >>> bob.decode(alice_message)
    Traceback (most recent call last):
      File "<input>", line 1, in <module>
      File "stringphone/topic.py", line 166, in decode
        "Verification key for participant not found."
    UntrustedKeyError: Verification key for participant not found.

    # String phone has raised an exception, as Bob has never seen Alice before
    # and does not trust her. We can decrypt the message anyway by disabling
    # signature verification, which is VERY VERY BAD.
    >>> bob.decode(alice_message, naive=True)
    'Hi Bob!'

    # If we don't want to be hassled by unkown messages, we can ignore
    # messages from untrusted participants:
    >>> bob.decode(alice_message, ignore_untrusted=True)

    # A much better way to do this is to have Bob trust Alice's public key:
    >>> bob.add_participant(alice.public_key)

    # Strict mode will also work now.
    >>> bob.decode(alice_message)
    'Hi Bob!'

    # Let's see what Alice thinks by having Bob reply back:
    >>> bob_message = bob.encode("Hey Alice!")

    # Alice will try to decrypt.
    >>> alice.decode(bob_message)
    Traceback (most recent call last):
      File "<input>", line 1, in <module>
      File "stringphone/topic.py", line 166, in decode
        "Verification key for participant not found."
    UntrustedKeyError: Verification key for participant not found.

    # Alice doesn't trust Bob either. We can fix this the same way as before and
    # restore order in the universe:
    >>> alice.add_participant(bob.public_key)

    # That's it for simple communication! We can look into discovering participants
    # and how to trust them in the "Discovery" section.


.. toctree::
   :hidden:
   :maxdepth: 2

   Home <self>
   protocol
   API documentation <stringphone>

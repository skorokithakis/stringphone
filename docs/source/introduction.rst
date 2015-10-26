Introduction
============

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
    # If you don't care about making sure that devices are who they claim to be,
    # you can just use this and you're done.
    >>> bob.decode(alice_message, naive=True)
    'Hi Bob!'

    # If we don't want to be hassled by unkown messages, we can ignore
    # messages from untrusted participants:
    >>> bob.decode(alice_message, ignore_untrusted=True)

    # A much better way to communicate is to have Bob trust Alice's public key.
    # This is done offline, after receiving the public key from Alice in some
    # secure manner. It can also be done through the discovery process, which is
    # detailed later on.
    >>> bob.add_participant(alice.public_key)

    # Strict mode will work now.
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


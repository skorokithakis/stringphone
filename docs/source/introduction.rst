Introduction
============

.. _getting-started:

Getting started
---------------

We'll start with a simple case. We will create two participants, one called
*Alice* and one called *Bob*, both of whom know the topic key already (they have
communicated beforehand over a secure channel and shared the topic key.  Let's
get them to exchange messages securely::

    >>> from stringphone import Topic, generate_signing_key_seed, generate_topic_key

    # Let's generate a topic key to share between the participants.
    #  generate_topic_key() uses a cryptographically secure RNG, so
    # you're safe using it to generate your keys.
    >>> topic_key = generate_topic_key()

    >>> topic_key
    ']j\x9b\xf7\xe77\x07h\xdcF\x82\x95\x0fo\x06\x90\xe1]R\xff\x8a\xeal\xd0\xef\x89J\xbd\x97\xf1[\xb4'

    # Each participant generates a seed for their signing key and stores it.
    # This key is their identity, so they must keep it completely secret from
    # everyone, and safe.
    >>> alice_seed = generate_signing_key_seed()
    >>> bob_seed = generate_signing_key_seed()

    # Give Alice and Bob their seeds, and the shared topic key.
    >>> alice = Topic(alice_seed, topic_key)
    >>> bob = Topic(bob_seed, topic_key)

    # Alice encodes a message to send to Bob. encode() encrypts and signs it.
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


Discovery
---------

Discovery is a way for participants to join the topic without any prior
knowledge, and for them to trust each other. In short, when a participant joins
a topic, it can request the topic key from the other participants already in
that topic. It can also request that new participants trust its public key so
they can later verify its messages.

The flow is:

* Call `construct_intro <stringphone.topic.Topic.construct_intro>` on the
  participant that needs the topic key (or at least wants the other participants
  to acknowledge it and trust its key).  This returns the message, which can
  then be sent down the channel.
* Call `construct_reply <stringphone.topic.Topic.construct_reply>` on one or
  more participants that already have the topic key. This creates the reply
  message that contains the encrypted topic key, which can then be sent.
* Call `parse_reply <stringphone.topic.Topic.parse_reply>` to extract the
  `topic_key <stringphone.topic.Topic.topic_key` from the response and save it
  in the `Topic <stringphone.topic.Topic>`. The `encode
  <stringphone.topic.Topic.encode>` and `decode
  <stringphone.topic.Topic.decode>` methods will then be able to encrypt and
  decrypt messages so other participants can read them and reply.

Here's a quick annotated demonstration of how to do this::

    >>> from stringphone import Message, Topic, generate_topic_key

    # Instantiate two participants, Alice with a topic key and Bob without one.
    # Bob will use the discovery protocol to request the key from Alice.
    >>> alice = Topic(topic_key=generate_topic_key())
    >>> bob = Topic()

    # Bob doesn't have a key, so he must ask for one. The way to do this is by
    # constructing and sending an intro message to Alice.
    >>> intro = bob.construct_intro()

    # Alice will receive the message and try to decode it, but an exception will
    # be raised, since the message is an introduction.
    >>> alice.decode(intro)
    Traceback (most recent call last):
      File "<input>", line 1, in <module>
      File "stringphone/topic.py", line 371, in decode
        raise IntroductionError("The received message is an introduction.")
    IntroductionError: The received message is an introduction.

    # Alice wraps the message in the Message convenience class and retrieves
    # the sender's (Bob's) public key.
    >>> message = Message(intro)
    >>> message.sender_key
    '\x0f\x83\xc7\xcb52\xe5,q\xba\xed\x94\xab\xd9\xb5\xfc=\x8d\x13\xa2\xeb\x19\x84\x0f9\xba\xeb\xa2\tR\x08\x10'

    # Realistically, Alice will decide to reply to the intro because of a
    # message dialog that will ask the user whether they want to trust the
    # Bob, or because of a pairing period where Alice will trust all devices
    # that introduce themselves in the next 10 seconds.
    # Never unconditionally trust devices, or you will let anyone join the topic
    # and security will be invalidated.
    >>> alice.add_participant(message.sender_key)

    # Construct and send the reply.
    >>> reply = alice.construct_reply(message)

    # Bob will try to decode, producing another exception, which is how he will
    # will realize that this is a reply.
    >>> bob.decode(reply)
    Traceback (most recent call last):
      File "<input>", line 1, in <module>
      File "stringphone/topic.py", line 375, in decode
        "The received message is an introduction reply.")
    IntroductionReplyError: The received message is an introduction reply.

    # Bob will parse the reply, which will populate the topic with the
    # topic key and return True to indicate success.
    >>> bob.parse_reply(reply)
    True

    # Bob decides to trust the participant that sent him the key (i.e. Alice).
    # Never trust participants unconditionally.
    >>> bob.add_participant(reply.sender_key)

    # Now the participants can freely and securely talk to each other.
    >>> message = bob.encode(b"Hey, Alice! Thanks for the key!")
    >>> alice.decode(message)
    'Hey, Alice! Thanks for the key!'
    >>> message = alice.encode(b"Hey Bob! No problem!")
    >>> bob.decode(message)
    'Hey Bob! No problem!'

This was a short summary of how discovery works. You should now be able to use
all of string telephone to exchange encrypted messages between participants and
announce your clients to the world, as well as send the encryption key between
them.

From here, you can continue to the :doc:`protocol` documentation to learn more
details about how string phone works at a lower level, or go to the
:doc:`API documentation <stringphone>` to find more information about how the
code is structured.

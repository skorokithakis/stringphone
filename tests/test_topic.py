import pytest
from hypothesis import given
from hypothesis.strategies import binary

from stringphone import Topic, Message
from stringphone import generate_topic_key
from stringphone.exceptions import (
    BadSignatureError, IntroductionError, IntroductionReplyError
)


@given(binary())
def test_decoding_inverts_encoding(bytestring):
    topic_key = generate_topic_key()
    c1 = Topic(topic_key=topic_key)
    c2 = Topic(topic_key=topic_key)
    assert c1.decode(c2.encode(bytestring), naive=True) == bytestring


@given(binary())
def test_decoding_own_messages(bytestring):
    c = Topic(topic_key=generate_topic_key())
    assert c.decode(c.encode(bytestring)) is None


@given(binary())
def test_ignore_untrusted(bytestring):
    topic_key = generate_topic_key()
    master = Topic(topic_key=topic_key)
    slave = Topic(topic_key=topic_key)

    assert slave.decode(
        master.encode(bytestring),
        ignore_untrusted=True) is None

    master.add_participant(slave.public_key)
    assert master.decode(slave.encode(bytestring), naive=True) == bytestring


@given(binary())
def test_naive_agreement(bytestring):
    topic_key = generate_topic_key()
    master = Topic(topic_key=topic_key)
    slave = Topic(topic_key=topic_key)

    assert slave.decode(master.encode(bytestring), naive=True) == bytestring
    assert master.decode(slave.encode(bytestring), naive=True) == bytestring


@given(binary())
def test_simple_agreement(bytestring):
    topic_key = generate_topic_key()
    master = Topic(topic_key=topic_key)
    slave = Topic(topic_key=topic_key)

    master.add_participant(slave.public_key)
    slave.add_participant(master.public_key)

    assert slave.decode(master.encode(bytestring)) == bytestring
    assert master.decode(slave.encode(bytestring)) == bytestring


@given(binary())
def test_discovery(bytestring):
    master = Topic(topic_key=generate_topic_key())
    slave = Topic()

    # Construct the introduction on the slave.
    intro = slave.construct_intro()

    # Attempt to read the introduction on the master.
    with pytest.raises(IntroductionError):
        master.decode(intro)

    # Trust the slave.
    public_key = Message(intro).sender_key
    master.add_participant(public_key)

    # If the intro contains a public key that didn't sign
    # the encryption key, assert that we raise an error.
    bad_intro = intro[0] + master.public_key + intro[33:]
    with pytest.raises(BadSignatureError):
        master.construct_reply(bad_intro)

    # Reply to the slave with the encrypted topic key.
    reply = master.construct_reply(intro)

    # Assert that decoding the reply returns None (because it's not addressed
    # to us).

    # Assert that the reply raises IntroductionReplyError (because it's a reply,
    # not a simple message).
    with pytest.raises(IntroductionReplyError):
        slave.decode(reply)

    # Trust the master on the slave.
    public_key = Message(reply).sender_key
    slave.add_participant(public_key)

    # Decode the introduction reply, getting the topic key.
    slave.parse_reply(reply)

    # Now we can decrypt all messages.
    assert slave.decode(master.encode(bytestring)) == bytestring
    assert master.decode(slave.encode(bytestring)) == bytestring

import pytest
from hypothesis import given
from hypothesis.strategies import binary

from stringphone import Topic
from stringphone import generate_signing_key_seed, generate_topic_key
from stringphone.exceptions import IntroductionError, IntroductionReplyError


@given(binary())
def test_decoding_inverts_encoding(bytestring):
    topic_key = generate_topic_key()
    c1 = Topic(generate_signing_key_seed(), topic_key)
    c2 = Topic(generate_signing_key_seed(), topic_key)
    assert c1.decode(c2.encode(bytestring), naive=True) == bytestring


@given(binary())
def test_decoding_own_messages(bytestring):
    c = Topic(generate_signing_key_seed(), generate_topic_key())
    assert c.decode(c.encode(bytestring)) is None


@given(binary())
def test_ignore_untrusted(bytestring):
    topic_key = generate_topic_key()
    master = Topic(generate_signing_key_seed(), topic_key)
    slave = Topic(generate_signing_key_seed(), topic_key)

    assert slave.decode(master.encode(bytestring), ignore_untrusted=True) is None

    master.add_participant(slave.public_key)
    assert master.decode(slave.encode(bytestring), naive=True) == bytestring


@given(binary())
def test_naive_agreement(bytestring):
    topic_key = generate_topic_key()
    master = Topic(generate_signing_key_seed(), topic_key)
    slave = Topic(generate_signing_key_seed(), topic_key)

    assert slave.decode(master.encode(bytestring), naive=True) == bytestring
    assert master.decode(slave.encode(bytestring), naive=True) == bytestring


@given(binary())
def test_simple_agreement(bytestring):
    topic_key = generate_topic_key()
    master = Topic(generate_signing_key_seed(), topic_key)
    slave = Topic(generate_signing_key_seed(), topic_key)

    master.add_participant(slave.public_key)
    slave.add_participant(master.public_key)

    assert slave.decode(master.encode(bytestring)) == bytestring
    assert master.decode(slave.encode(bytestring)) == bytestring


@given(binary())
def test_discovery(bytestring):
    master = Topic(generate_signing_key_seed(), generate_topic_key())
    slave = Topic(generate_signing_key_seed())

    # Construct the introduction on the slave.
    intro = slave.construct_introduction()

    # Attempt to read the introduction on the master.
    with pytest.raises(IntroductionError):
        master.decode(intro)

    # Trust the slave.
    public_key = master.get_message_info(intro)["participant_key"]
    master.add_participant(public_key)

    # Reply to the slave with the encrypted topic key.
    reply = master.construct_introduction_reply(intro)

    # Assert that the reply raises IntroductionReplyError.
    with pytest.raises(IntroductionReplyError):
        slave.decode(reply)

    # Trust the master on the slave.
    public_key = slave.get_message_info(reply)["participant_key"]
    slave.add_participant(public_key)

    # Decode the introduction reply, getting the topic key.
    slave.decode_introduction_reply(reply)

    # Now we can decrypt all messages.
    assert slave.decode(master.encode(bytestring)) == bytestring
    assert master.decode(slave.encode(bytestring)) == bytestring

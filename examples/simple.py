import stringphone

# Generate the pre-shared topic key.
key = stringphone.generate_topic_key()

# Instantiate three participants, each with a copy of the key. In practice,
# these will be distinct devices.
t1 = stringphone.Topic(stringphone.generate_signing_key_seed(), key)
t2 = stringphone.Topic(stringphone.generate_signing_key_seed(), key)
t3 = stringphone.Topic(stringphone.generate_signing_key_seed(), key)

# Encode a message to the topic.
encoded1 = t1.encode(b"Hey guys! This is t1!")

# Both other participants can read the message.
print(t2.decode(encoded1, naive=True))
print(t3.decode(encoded1, naive=True))

# Reply to t1 with another message.
encoded2 = t2.encode(b"Hi t1! This is t2, I got your message.")

# Similarly, this message will also be readable by both other participants.
print(t1.decode(encoded2, naive=True))
print(t3.decode(encoded2, naive=True))

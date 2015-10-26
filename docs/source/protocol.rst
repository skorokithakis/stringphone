Protocol
--------

This page details the messaging protocol and the format of the messages. It is
an in-depth explanation of the internals of string phone. If all you want to do
is use the library, you don't need to know any of this.


Cryptography
============

This is going to be short. String phone uses NaCl, as the "gold standard" in
cryptography, and does whatever NaCl does. Keys are generated using NaCl's
functions, signing is done using NaCl's signing methods, and symmetric and
asymmetric encryption are as well. In short, it's NaCl all the way, with
minimal novelty.

To delve into the lower layers a bit, NaCl uses Salsa20 for symmetric
encryption and Poly1305 for authentication. Each message uses a new,
randomly-generated nonce, which may not be enough when sending many short
messages. A potential future improvement would be to use XSalsa20 for the
longer nonce.

For specifics, please refer to the `PyNaCl documentation
<http://pynacl.readthedocs.org/>`_.


Discovery
=========

In the simple case, every participant already has the shared topic key and the
keys and IDs of every other participant that they are interested in. Obviously,
if you don't care about receiving or authenticating a participant's messages,
you don't need their public key.  More frequently, though, a participant will
start out not knowing anyone, or the key. This is where discovery comes in.


Introduction
^^^^^^^^^^^^

Discovery is done through introductions. When a participant joins a channel, it
can send an introduction message (obtained through
:py:meth:`construct_introduction()
<stringphone.topic.Topic.construct_introduction>`) to request the topic key
from other participants. This contains the new participant's signing key (so it
can identify subsequent messages to others) and its encryption key, with which
the topic key will be encrypted.


Reply
^^^^^

A participant may choose to reply to an introduction. It can also just ignore
the introduction, if it's not expecting any new participants. If the
participant chooses to reply to the introduction, it can construct a reply with 
:py:meth:`construct_introduction_reply(introduction)
<stringphone.topic.Topic.construct_introduction_reply>`. The reply contains the
encrypted topic key, the encryption key (for verification) and the signing key
of the replying participant, as the new participant may want to trust the
former.

The new node parses this and decrypts the topic key, which it then uses to post
messages to and read messages from the topic.


Message format
==============

Messages are delimited by size. All message formats start with a single-byte
header that indicates the type of the message. The rest of the message varies
according to its type. Details on all message types are elaborated on below.

Message
^^^^^^^

The simple message is the main way of communication. It contains the ID of the
participant that sent the message (for identification and as a way to find the
public key for verification), a signature and the ciphertext.

The entire message (including the participant ID and ciphertext) is signed by
the participant's signing key.

+-----------+------------+-----------+----------------+-----------------------+
| **Part**  | Type ("m") | Signature | Participant ID | Ciphertext            |
+-----------+------------+-----------+----------------+-----------------------+
| **Size**  | 1 byte     | 64 bytes  | 16 bytes       | Variable              |
+-----------+------------+-----------+----------------+-----------------------+


Introduction
^^^^^^^^^^^^

The introduction contains the participant's signing key (from which the
participant's ID can be derived), and their encryption key.

+-----------+------------+-------------+----------------+
| **Part**  | Type ("i") | Signing key | Encryption key |
+-----------+------------+-------------+----------------+
| **Size**  | 1 byte     | 32 bytes    | 32 bytes       |
+-----------+------------+-------------+----------------+


Reply
^^^^^

The introduction reply contains the encrypted topic key for the current topic,
the public encryption key that was used to encrypt it (for signature
verification) and the signing key of the participant who sent the reply.

+-----------+------------+---------------------+----------------+-------------+
| **Part**  | Type ("r") | Encrypted topic key | Encryption key | Signing key |
+-----------+------------+---------------------+----------------+-------------+
| **Size**  | 1 byte     | 72 bytes            | 32 bytes       | 32 bytes    |
+-----------+------------+---------------------+----------------+-------------+

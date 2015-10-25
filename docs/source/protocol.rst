Protocol
--------

This page details the messaging protocol and the format of the messages. It is
an in-depth explanation of the internals of string phone. If all you want to do
is use the library, you don't need to know any of this.

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

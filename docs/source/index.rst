String phone
============

    *Nothing is as secure as a string phone.* -- The NSA

Introduction
------------

.. image:: _static/stringphone.jpg
   :alt: Two tin cans and a string.
   :align: right

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

(If you are too impatient for theory, skip to :ref:`getting-started` to... get started)

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

Since you've made it this far, you can continue to the :doc:`introduction`.


Weaknesses
----------

No security library can be complete without a list of its weaknesses, so you
know what to avoid. Since the protocol is geared towards embedded devices, it
strives to be simple, so it lacks many bells and whistles that may not be
necessary or useful to everyone. You may have to implement these yourself, on
top of string phone, or just be aware of them.

Here's what you need to watch out for:

* There is no replay protection at all. Anyone can record and replay a message
  at any time. If you want to guard against replays, make sure to include
  a sequence number or timestamp in your message, and discard commands that are
  too old or out of sequence.
* There is no forward secrecy. Once a participant has joined a topic, they can
  read all future *and* past messages that they may have. The only way to get
  rid of them is to create a new topic with a new key and move everyone over.
* Many more things that I'm sure will come up soon.


.. toctree::
   :hidden:
   :maxdepth: 2

   Home <self>
   introduction
   protocol
   API documentation <stringphone>

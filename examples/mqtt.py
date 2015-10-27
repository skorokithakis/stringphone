import sys

import codecs
import stringphone
import paho.mqtt.client as mqtt

TOPIC_NAME = "stringphone"


def send(client, message):
    """
    A simple convenience function to avoid repetition.
    """
    client.publish(TOPIC_NAME, bytearray(codecs.encode(message, "hex")))


def on_connect(client, userdata, flags, rc):
    """
    The operations to perform when connecting to MQTT.
    """
    print("Participant %s: Connected with id %s!" %
          (id, codecs.encode(topic.id, "hex")))
    client.subscribe(TOPIC_NAME)

    # Introduce ourselves to the channel, to hopefully get other
    # participants to trust us.
    send(client, topic.construct_introduction())


def on_message(client, userdata, msg):
    """
    The operations to perform on receiving a new message.
    """
    # Decode the payload.
    payload = codecs.decode(msg.payload, "hex")
    try:
        # Try to decode the message.
        message = topic.decode(payload)
        if message:
            # Print the decoded message, if we didn't drop it.
            print(message)
    except stringphone.exceptions.IntroductionError:
        info = topic.get_message_info(payload)
        print("Participant %s: New participant with ID %s joined, should I"
              " trust them? Since you can't really reply, I'll assume you"
              " said yes." %
              (id, codecs.encode(info["sender_id"], "hex")))
        # Trust the participant that just introduced itself.
        topic.add_participant(info["sender_key"])
        # Construct the reply that contains the topic key.
        reply = topic.construct_introduction_reply(payload)
        print("Sending reply...")
        send(client, reply)
    except stringphone.exceptions.IntroductionReplyError:
        # Decode the received introduction reply.
        print("Decoding reply...")
        topic.decode_introduction_reply(payload)
        send(client, topic.encode(bytearray("Hey guys! This is participant %s." % id, "ascii")))


def main(topic, id):
    """
    Connect to MQTT.
    """
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message

    client.connect("test.mosquitto.org", 1883, 60)
    client.loop_forever()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: mqttsample.py <numeric id, starting at 1>")

    id = int(sys.argv[1])

    if id == 1:
        topic_key = stringphone.generate_topic_key()
    else:
        topic_key = None

    topic = stringphone.Topic(stringphone.generate_signing_key_seed(),
                              topic_key)

    main(topic, id)

"""
Symmetric and asymmetric cryptography- and signing-related classes and methods.
"""
import nacl.encoding
import nacl.exceptions
import nacl.secret
import nacl.signing
import nacl.public
import nacl.utils
import six

from .exceptions import BadSignatureError


def generate_topic_key():
    """
    Generate and return a new topic key. The generated key is cryptographically
    secure.

    :return: A cryptographically secure random topic key.
    :rtype: bytes
    """
    return nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)


def generate_signing_key_seed():
    """
    Generate and return a new signing key seed. The generated seed is
    cryptographically secure.

    :return: A cryptographically secure random signing key seed.
    :rtype: bytes
    """
    return nacl.signing.SigningKey.generate().encode()


class AsymmetricCrypto:
    def __init__(self):
        self._private_key = nacl.public.PrivateKey.generate()

    def encrypt(self, plaintext, public_key):
        """
        Asymmetrically encrypt and sign the plaintext to the given public key.

        :param bytes plaintext: The plaintext to encrypt.
        :param bytes public_key: The recipient's public encryption key.

        :return: The ciphertext.
        :rtype: bytes
        """
        box = nacl.public.Box(
            self._private_key, nacl.public.PublicKey(public_key)
        )
        nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
        ciphertext = box.encrypt(plaintext, nonce)
        return ciphertext

    def decrypt(self, ciphertext, public_key):
        """
        Asymmetrically decrypt and verify the ciphertext.

        :param bytes plaintext: The ciphertext to decrypt.
        :param bytes public_key: The sender's public encryption key.

        :return: The plaintext.
        :rtype: bytes
        """
        box = nacl.public.Box(
            self._private_key, nacl.public.PublicKey(public_key)
        )
        return box.decrypt(ciphertext)

    @property
    def public_key(self):
        """
        The public encryption key of the AsymmetricCrypto object.

        :rtype: bytes
        """
        return self._private_key.public_key.encode()


class SymmetricCrypto:
    def __init__(self, key):
        self._box = nacl.secret.SecretBox(key)

    def encrypt(self, plaintext):
        """
        Encrypt the plaintext.

        :param bytes plaintext: The plaintext to encrypt.

        :return: The ciphertext.
        :rtype: bytes
        """
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        return six.binary_type(self._box.encrypt(plaintext, nonce))

    def decrypt(self, ciphertext):
        """
        Decrypt the ciphertext.

        :param bytes ciphertext: The ciphertext to decrypt.

        :return: The ciphertext.
        :rtype: bytes
        """
        return self._box.decrypt(ciphertext)


class Signer:
    def __init__(self, private_key):
        """
        Instantiate a new Signer.

        :param bytes private_key: The private signing key to use.
        """
        self._signer = nacl.signing.SigningKey(private_key)

    def sign(self, plaintext):
        """
        Sign the given plaintext.

        :param bytes plaintext: The plaintext to sign.

        :return: The signed plaintext.
        :rtype: bytes
        """
        signed = self._signer.sign(plaintext)
        return six.binary_type(signed)

    @property
    def public_key(self):
        """
        The public key of this Signer object.

        :rtype: bytes
        """
        return self._signer.verify_key.encode()


class Verifier:
    def __init__(self, public_key):
        """
        Instantiate a new Verifier.

        :param bytes public_key: The public signing key to use.
        """
        self._verifier = nacl.signing.VerifyKey(public_key)

    def verify(self, signed):
        """
        Verify the signature of a signed bytestring.

        :return: The plaintext that was signed with a valid
            signature.
        :rtype: bytes
        :raises BadSignatureError: The signature was invalid.
        """
        try:
            plaintext = self._verifier.verify(signed)
        except nacl.exceptions.BadSignatureError as e:
            raise BadSignatureError(str(e))
        return plaintext

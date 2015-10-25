import nacl.encoding
import nacl.exceptions
import nacl.secret
import nacl.signing
import nacl.public
import nacl.utils
import six

from .exceptions import BadSignatureError


def generate_topic_key():
    "Generate and return a new symmetric cryptography key."
    return nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)


def generate_signing_key():
    "Generate and return a new signing key."
    return nacl.signing.SigningKey.generate().encode()


class AsymmetricCrypto:
    def __init__(self):
        self._private_key = nacl.public.PrivateKey.generate()

    def encrypt(self, plaintext, public_key):
        box = nacl.public.Box(self._private_key,
                              nacl.public.PublicKey(public_key))
        nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
        ciphertext = box.encrypt(plaintext, nonce)
        return ciphertext

    def decrypt(self, ciphertext, public_key):
        box = nacl.public.Box(self._private_key,
                              nacl.public.PublicKey(public_key))
        return box.decrypt(ciphertext)

    @property
    def public_key(self):
        return self._private_key.public_key.encode()


class SymmetricCrypto:
    def __init__(self, key):
        self._box = nacl.secret.SecretBox(key)

    def encrypt(self, plaintext):
        """
        Encrypt the plaintext (a bytestring) and return the
        binary ciphertext.
        """
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        return six.binary_type(self._box.encrypt(plaintext, nonce))

    def decrypt(self, ciphertext):
        """
        Decrypt the given ciphertext and return the plaintext.
        """
        return self._box.decrypt(ciphertext)


class Signer:
    def __init__(self, private_key):
        self._signer = nacl.signing.SigningKey(private_key)

    def sign(self, plaintext):
        """
        Sign the given plaintext (a bytestring).
        """
        signed = self._signer.sign(plaintext)
        return six.binary_type(signed)

    @property
    def public_key(self):
        return self._signer.verify_key.encode()


class Verifier:
    def __init__(self, public_key):
        """
        Instantiate a new Verifier, given a hex-encoded signing key.
        """
        self._verifier = nacl.signing.VerifyKey(public_key)

    def verify(self, signed):
        """
        Verify the signature of a signed bytestring.

        Returns the plaintext if the signature is valid, raises an exception
        otherwise.
        """
        try:
            plaintext = self._verifier.verify(signed)
        except nacl.exceptions.BadSignatureError as e:
            raise BadSignatureError(str(e))
        return plaintext

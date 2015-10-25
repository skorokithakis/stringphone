from hypothesis import given
from hypothesis.strategies import binary

from .crypto import (
    Signer, SymmetricCrypto, generate_signing_key, generate_topic_key, Verifier
)


@given(binary())
def test_decryption_inverts_encryption(bytestring):
    c = SymmetricCrypto(generate_topic_key())
    assert c.decrypt(c.encrypt(bytestring)) == bytestring


@given(binary())
def test_verification_inverts_signing(bytestring):
    s = Signer(generate_signing_key())
    v = Verifier(s.public_key)
    assert v.verify(s.sign(bytestring)) == bytestring

from hypothesis import given
from hypothesis.strategies import binary

from stringphone.crypto import (
    Signer, AsymmetricCrypto, SymmetricCrypto, generate_signing_key,
    generate_topic_key, Verifier
)


@given(binary())
def test_asymmetric_decryption_inverts_encryption(bytestring):
    a1 = AsymmetricCrypto()
    a2 = AsymmetricCrypto()
    assert a2.decrypt(
        a1.encrypt(bytestring, a2.public_key), a1.public_key
    ) == bytestring


@given(binary())
def test_symmetric_decryption_inverts_encryption(bytestring):
    c = SymmetricCrypto(generate_topic_key())
    assert c.decrypt(c.encrypt(bytestring)) == bytestring


@given(binary())
def test_verification_inverts_signing(bytestring):
    s = Signer(generate_signing_key())
    v = Verifier(s.public_key)
    assert v.verify(s.sign(bytestring)) == bytestring

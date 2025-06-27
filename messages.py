from message_fields import *

from abc import ABC
import struct
from typing import *
from dataclasses import dataclass

# Main "outer" messages.

class OpcMessage(ABC):
  def __init__(self, **field_values):
    for name, ftype in self.fields:
      setattr(self, name, field_values.get(name, ftype.default_value))
  
  @property
  @abstractmethod
  def messagetype() -> str:
    ...
    
  @property
  @abstractmethod
  def fields() -> list[tuple[str, FieldType]]:
    ...
    
  def to_bytes(self) -> bytes:
    mtype = self.messagetype.encode()
    assert len(mtype) == 3
    
    body = b''
    for name, ftype in self.fields:
      value = getattr(self, name)
      body += ftype.to_bytes(value)
    
    return mtype + b'F' + struct.pack('<I', len(body) + 8) + body

  def from_bytes(self, reader : BinaryIO, allow_chunking : bool = False) -> bool:
    # Note: when this throws a ServerError the message is still consumed in its entirety from the reader.
    # Returns whether this is the final chunk.
    
    mtype = reader.read(3)
    decodecheck(len(mtype) == 3, 'Connection unexpectedly terminated.')
    decodecheck(mtype == self.messagetype.encode() or mtype == b'ERR', 'Unexpected message type')
    
    ctype = reader.read(1)
    
    decodecheck(ctype == b'F' or ctype == b'C')
    decodecheck(ctype == b'F' or allow_chunking, f'Unexpected chunked message.')
    
    bodylen = struct.unpack('<I', reader.read(4))[0] - 8
    body = reader.read(bodylen)
    
    if mtype == b'ERR' and self.messagetype != 'ERR':
      # Server error. Parse for exception.
      errorcode, tail = IntField().from_bytes(body)
      reason, _ = StringField().from_bytes(tail)
      raise ServerError(errorcode, reason)
    
    for name, ftype in self.fields:
      value, body = ftype.from_bytes(body)
      setattr(self, name, value)
    
    return ctype == b'F'

  def get_field_location(self, fieldname : str) -> int:
    '''Returns binary (offset, length) of a specific field within the result of self.to_bytes()'''
    
    offset = 8
    for name, ftype in self.fields:
      value = getattr(self, name)
      valsize = len(ftype.to_bytes(value))
      if name == fieldname:
        return offset, valsize
      else:
        offset += valsize
        
    raise Exception(f'Field {fieldname} does not exist.')
    
  def sign_and_encrypt(self, 
    signer : Callable[[bytes], bytes], encrypter : Optional[Callable[[bytes], bytes]],
    plainblocksize : int, cipherblocksize : int, sigsize : int
  ):
    '''Applies OPC's weird padding scheme and sign/encrypt combo to TrailingBytes of the message.'''
    
    trailname, trailtype = self.fields[-1]
    assert isinstance(trailtype, TrailingBytes)
    plaintext = getattr(self, trailname)
    
    # Length calculations.
    padbyte = plainblocksize - (len(plaintext) + 1 + sigsize) % plainblocksize
    padding = (padbyte + 1) * bytes([padbyte])
    ptextsize = len(plaintext) + len(padding) + sigsize
    ctextsize = (ptextsize // plainblocksize) * cipherblocksize
    
    # Add padding and adjust length to obtain signature input.
    setattr(self, trailname, plaintext + padding)
    siginput = self.to_bytes()
    siginput = siginput[:4] + IntField().to_bytes(len(siginput) - len(plaintext) - len(padding) + ctextsize) + siginput[8:]
    signature = signer(siginput)
    
    # Encrypt plaintext, padding and signature.
    ciphertext = encrypter(plaintext + padding + signature)
    assert len(ciphertext) == ctextsize
    setattr(self, trailname, ciphertext)
    
    assert(len(self.to_bytes()) == len(siginput) - len(plaintext) - len(padding) + ctextsize)
    
  def sign(self, signer : Callable[[bytes], bytes], sigsize : int):
    '''Message signing without encryption and padding.'''
    trailname, trailtype = self.fields[-1]
    assert isinstance(trailtype, TrailingBytes)
    siginput = self.to_bytes()
    siginput = siginput[:4] + IntField().to_bytes(len(siginput) + sigsize) + siginput[8:]
    signature = signer(siginput)
    setattr(self, trailname, getattr(self, trailname) + signature)
    
    
# Messages.
    
class HelloMessage(OpcMessage): 
  messagetype = 'HEL'
  fields = [
    ('version', IntField()),
    ('receiveBufferSize', IntField()),
    ('sendBufferSize', IntField()),
    ('maxMessageSize', IntField()),
    ('maxChunkCount', IntField()),
    ('endpointUrl', StringField()),
  ]
  
class AckMessage(OpcMessage):
  messagetype = 'ACK'
  fields = [
    ('version', IntField()),
    ('receiveBufferSize', IntField()),
    ('sendBufferSize', IntField()),
    ('maxMessageSize', IntField()),
    ('maxChunkCount', IntField()),
  ]

class OpenSecureChannelMessage(OpcMessage):
  messagetype = 'OPN'
  fields = [
    ('secureChannelId', IntField()),
    ('securityPolicyUri', SecurityPolicyField()),
    ('senderCertificate', ByteStringField()),
    ('receiverCertificateThumbprint', ByteStringField()),
    ('encodedPart', TrailingBytes()),
  ]
  
class ConversationMessage(OpcMessage):
  messagetype = 'MSG'
  fields = [
    ('secureChannelId', IntField()),
    ('tokenId', IntField()),
    ('encodedPart', TrailingBytes())
  ]
  
encodedConversation = ObjectField('EncodedConversation', [
  ('sequenceNumber', IntField()),
  ('requestId', IntField()),
  ('requestOrResponse', TrailingBytes()),
])

# Enumerations.
class SecurityTokenRequestType(IntEnum):
  ISSUE = 0
  RENEW = 1
  
class MessageSecurityMode(IntEnum):
  INVALID          = 0
  NONE             = 1
  SIGN             = 2
  SIGN_AND_ENCRYPT = 3
  
class ApplicationType(IntEnum):
  SERVER          = 0
  CLIENT          = 1
  CLIENTANDSERVER = 2
  DISCOVERYSERVER = 3
  
class UserTokenType(IntEnum):
  ANONYMOUS   = 0
  USERNAME    = 1
  CERTIFICATE = 2
  ISSUEDTOKEN = 3
  
class TimestampsToReturn(IntEnum):
  SOURCE  = 0 
  SERVER  = 1 
  BOTH    = 2 
  NEITHER = 3 
  INVALID = 4 
  
class BrowseDirection(IntEnum):
  FORWARD = 0
  INVERSE = 1
  BOTH    = 2
  INVALID = 3
  
class NodeClass(IntEnum):
  UNSPECIFIED   = 0
  OBJECT        = 1
  VARIABLE      = 2
  METHOD        = 4
  OBJECTTYPE    = 8
  VARIABLETYPE  = 16
  REFERENCETYPE = 32
  DATATYPE      = 64
  VIEW          = 128
  

# Encoded requests and responses. Based on UA-.NETStandard/Stack/Opc.Ua.Core/Schema/{NodeIds.csv,Opc.Ua.Types.bsd}
# and UA-.NETStandard/Stack/Opc.Ua.Core/Types/Encoders/BinaryEncoder.cs
requestHeader = ObjectField('RequestHeader', [
    ('authenticationToken', NodeIdField()),
    ('timeStamp', DateTimeField()),
    ('requestHandle', IntField()),
    ('returnDiagnostics', IntField()),
    ('auditEntryId', StringField()),
    ('timeoutHint', IntField()),
    ('additionalHeader', ExtensionObjectField()),
  ])

responseHeader = ObjectField('ResponseHeader', [
    ('timeStamp', DateTimeField()),
    ('requestHandle', IntField()),
    ('serviceResult', IntField()),
    ('serviceDiagnostics', FixedBytes(b'\x00')), # Just assume this stays empty for now. 
    ('stringTable', ArrayField(StringField())),
    ('additionalHeader', ExtensionObjectField()),
  ])

applicationDescription = ObjectField('ApplicationDescription', [
    ('applicationUri', StringField()),
    ('productUri', StringField()),
    ('applicationName', LocalizedTextField()),
    ('applicationType', EnumField(ApplicationType)),
    ('gatewayServerUri', StringField()),
    ('discoveryProfileUri', StringField()),
    ('discoveryUrls', ArrayField(StringField())),
  ])


openSecureChannelRequest = EncodableObjectField('OpenSecureChannelRequest', 446, [
    ('requestHeader', requestHeader),
    ('clientProtocolVersion', IntField()),
    ('requestType', EnumField(SecurityTokenRequestType)),
    ('securityMode', EnumField(MessageSecurityMode)),
    ('clientNonce', ByteStringField()),
    ('requestedLifetime', IntField()),
  ])

openSecureChannelResponse = EncodableObjectField('OpenSecureChannelResponse', 449, [
    ('responseHeader', responseHeader),
    ('serverProtocolVersion', IntField()),
    ('securityToken', ObjectField('ChannelSecurityToken', [
        ('channelId', IntField()),
        ('tokenId', IntField()),
        ('createdAt', DateTimeField()),
        ('revisedLifetime', IntField()),
      ])),
    ('serverNonce', ByteStringField()),
  ])

createSessionRequest = EncodableObjectField('CreateSessionRequest', 461, [
    ('requestHeader', requestHeader),
    ('clientDescription', applicationDescription),
    ('serverUri', StringField()),
    ('endpointUrl', StringField()),
    ('sessionName', StringField()),
    ('clientNonce', ByteStringField()),
    ('clientCertificate', ByteStringField()),
    ('requestedSessionTimeout', DoubleField()),
    ('maxResponseMessageSize', IntField()),
  ])

endpointDescription = ObjectField('EndpointDescription', [
    ('endpointUrl', StringField()),
    ('server', applicationDescription),
    ('serverCertificate', ByteStringField()),
    ('securityMode', EnumField(MessageSecurityMode)),
    ('securityPolicyUri', SecurityPolicyField()),
    ('userIdentityTokens', ArrayField(ObjectField('UserTokenPolicy', [
        ('policyId', StringField()),
        ('tokenType', EnumField(UserTokenType)),
        ('issuedTokenType', StringField()),
        ('issuerEndpointUrl', StringField()),
        ('securityPolicyUri', SecurityPolicyField()),
      ]))),
    ('transportProfileUri', StringField()),
    ('securityLevel', IntField('<B')),
  ])
signedSoftwareCertificate = ObjectField('SignedSoftwareCertificate', [
    ('certificateData', ByteStringField()),
    ('signature', ByteStringField()),
  ])
signatureData = ObjectField('SignatureData', [
    ('algorithm', StringField()),
    ('signature', ByteStringField()),
  ])

createSessionResponse = EncodableObjectField('CreateSessionResponse', 464, [
    ('responseHeader', responseHeader),
    ('sessionId', NodeIdField()),
    ('authenticationToken', NodeIdField()),
    ('revisedSessionTimeout', DoubleField()),
    ('serverNonce', ByteStringField()),
    ('serverCertificate', ByteStringField()),
    ('serverEndpoints', ArrayField(endpointDescription)),
    ('serverSoftwareCertificates', ArrayField(signedSoftwareCertificate)),
    ('serverSignature', signatureData),
    ('maxRequestMessageSize', IntField()),
  ])

activateSessionRequest = EncodableObjectField('ActivateSessionRequest', 467, [
    ('requestHeader', requestHeader),
    ('clientSignature', signatureData),
    ('clientSoftwareCertificates', ArrayField(signedSoftwareCertificate)),
    ('localeIds', ArrayField(StringField())),
    ('userIdentityToken', ExtensionObjectField()),
    ('userTokenSignature', signatureData),
  ])

activateSessionResponse = EncodableObjectField('ActivateSessionResponse', 470, [
    ('responseHeader', responseHeader),
    ('serverNonce', ByteStringField()),
    ('results', ArrayField(IntField())),
    ('diagnosticInfos', TrailingBytes()), # Not bothering to parse this
  ])

readValueId = ObjectField('ReadValueId', [
    ('nodeId', NodeIdField()),
    ('attributeId', IntField()),
    ('indexRange', StringField()),
    ('dataEncoding', QualifiedNameField()),
  ])

getEndpointsRequest = EncodableObjectField('GetEndpointsRequest', 428, [
    ('requestHeader', requestHeader),
    ('endpointUrl', StringField()),
    ('localeIds', ArrayField(StringField())),
    ('profileUris', ArrayField(StringField())),
])

getEndpointsResponse = EncodableObjectField('GetEndpointsResponse', 431, [
    ('responseHeader', responseHeader),
    ('endpoints', ArrayField(endpointDescription)),
])

readRequest = EncodableObjectField('ReadRequest', 631, [
    ('requestHeader', requestHeader),
    ('maxAge', DoubleField()),
    ('timestampsToReturn', EnumField(TimestampsToReturn)),
    ('nodesToRead', ArrayField(readValueId)),
  ])

readResponse = EncodableObjectField('ReadResponse', 634, [
    ('responseHeader', responseHeader),
    ('results', ArrayField(DataValueField())), 
    ('diagnosticInfos', TrailingBytes()),
  ])

viewDescription = ObjectField('ViewDescription', [
  ('viewId', NodeIdField()),
  ('timestamp', DateTimeField()),
  ('viewVersion', IntField()),
])

browseDescription = ObjectField('BrowseDescription', [
  ('nodeId', NodeIdField()), 
  ('browseDirection', EnumField(BrowseDirection)), 
  ('referenceTypeId', NodeIdField()), 
  ('includeSubtypes', BooleanField()), 
  ('nodeClassMask', IntField()), 
  ('resultMask', IntField()), 
])

browseRequest = EncodableObjectField('BrowseRequest', 527, [
  ('requestHeader', requestHeader), 
  ('view', viewDescription),
  ('requestedMaxReferencesPerNode', IntField()),
  ('nodesToBrowse', ArrayField(browseDescription)),  
])

browseResponse = EncodableObjectField('BrowseResponse', 530, [
  ('responseHeader', responseHeader), 
  ('results', ArrayField(ObjectField('BrowseResult', [
    ('statusCode', IntField()),
    ('continuationPoint', ByteStringField()),
    ('references', ArrayField(ObjectField('ReferenceDescription', [
      ('referenceTypeId', NodeIdField()),
      ('isForward', BooleanField()),
      ('nodeId', ExpandedNodeIdField()),
      ('browseName', QualifiedNameField()),
      ('displayName', LocalizedTextField()),
      ('nodeClass', EnumField(NodeClass)),
      ('typeDefinition', ExpandedNodeIdField()),
    ]))),
  ]))),
  ('diagnosticInfos', TrailingBytes()),
])

# Supported extension objects.
anonymousIdentityToken = ExtensionObjectField.register('AnonymousIdentityToken', 321, [
  ('policyId', StringField()),
])

userNameIdentityToken = ExtensionObjectField.register('UserNameIdentityToken', 324, [
  ('policyId', StringField()),
  ('userName', StringField()),
  ('password', ByteStringField()),
  ('encryptionAlgorithm', StringField()),
])

x509IdentityToken = ExtensionObjectField.register('X509IdentityToken', 327, [
  ('policyId', StringField()),
  ('certificateData', ByteStringField()),
])

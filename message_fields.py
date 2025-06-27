from abc import ABC, abstractmethod
import struct
from typing import *
from types import NoneType
from enum import Enum, auto, IntEnum
from datetime import datetime, timedelta
from binascii import hexlify
from collections import namedtuple
from base64 import b64encode, b64decode
from uuid import UUID
from dataclasses import dataclass

# Type vars.
ValType = TypeVar('ValType')
OriginalValType = TypeVar('OriginalValType')
ElementType = TypeVar('ElementType')

# Error checking.
class DecodeError(Exception):
  pass
  
# Thrown by from_bytes when an unexpected OPC error message is encountered.
class ServerError(Exception):
  def __init__(self, errorcode, reason):
    super().__init__(f'Server error {hex(errorcode)}: "{reason}"')
    self.errorcode = errorcode
  
def decodecheck(condition : bool, msg : str = 'Invalid OPC message syntax'):
  if not condition:
    raise DecodeError(msg)
    
class UnsupportedFieldException(Exception):
  def __init__(self, fieldname, msg):
    super().__init__(msg)
    self.fieldname = fieldname

# OPC-specific data types.
@dataclass
class NodeId:
  namespace: int
  identifier: int | str | bytes | UUID
  
  def __str__(self):
    prefix = f'ns={self.namespace};' if self.namespace != 0 else ''
    idval = repr(self.identifier)
    if type(self.identifier) == UUID:
      letter = 'g'
    elif type(self.identifier) == int:
      letter = 'i'
    elif type(self.identifier) == bytes:
      letter = 'b'
      idval = b64encode(self.identifier).decode()
    else:
      letter = 's'
    
    return f'{prefix}{letter}={idval}'
      
@dataclass 
class ExpandedNodeId:
  nodeId: NodeId
  namespaceUri: Optional[str]
  serverIndex: Optional[int]
  
class SecurityPolicy(Enum):
  NONE = 'None'
  BASIC128RSA15 = 'Basic128Rsa15'
  BASIC256 = 'Basic256'
  AES128_SHA256_RSAOAEP = 'Aes128_Sha256_RsaOaep'
  BASIC256SHA256 = 'Basic256Sha256'
  AES256_SHA256_RSAPSS = 'Aes256_Sha256_RsaPss'
  
@dataclass
class LocalizedText:
  locale : Optional[str] = None
  text   : Optional[str] = None
  
# Relevant field types (partially based on https://reference.opcfoundation.org/Core/Part6/v104/docs/5.2)

class FieldType(ABC, Generic[ValType]):
  @property
  @abstractmethod
  def default_value(self) -> ValType:
    ...
    
  @abstractmethod
  def to_bytes(self, value) -> bytes:
    ...
    
  @abstractmethod
  def from_bytes(self, bytestr : bytes) -> tuple[ValType, bytes]:
    ...  
  
class StructField(FieldType[ValType]):
  def __init__(self, fmt : str):
    super().__init__()
    self._format = fmt
    self._size = struct.calcsize(fmt)
  
  def to_bytes(self, value):
    return struct.pack(self._format, value)
    
  def from_bytes(self, bytestr):
    return struct.unpack(self._format, bytestr[:self._size])[0], bytestr[self._size:]  
  
class IntField(StructField[int]):
  default_value = 0
  
  def __init__(self, intformat : str = '<I'):
    super().__init__(intformat)
    
class DoubleField(StructField[float]):
  default_value = 0.0
  
  def __init__(self, floatformat : str = '<d'):
    super().__init__(floatformat)
    
class ByteStringField(FieldType[Optional[bytes]]):
  _lentype = IntField()
  
  default_value = b''
  
  def to_bytes(self, value):
    return self._lentype.to_bytes(len(value)) + value if value is not None else b'\xff\xff\xff\xff'
    
  def from_bytes(self, bytestr):
    if bytestr.startswith(b'\xff\xff\xff\xff'):
      return None, bytestr[4:]
    else:
      length, rest = self._lentype.from_bytes(bytestr)
      return rest[:length], rest[length:]
    
class FixedBytes(FieldType[NoneType]):
  def __init__(self, bytestr : bytes):
    self._bytestr = bytestr
    
  @property
  def default_value(self):
    return self._bytestr
  
  def to_bytes(self, value):
    assert value is None
    return self._bytestr
    
  def from_bytes(self, bytestr):
    decodecheck(bytestr.startswith(self._bytestr), f'Expected fixed bytes {hexlify(self._bytestr)}; instead got {hexlify(bytestr[:len(self._bytestr)])}')
    return None, bytestr[len(self._bytestr):]
  
class TransformedFieldType(Generic[ValType, OriginalValType], FieldType[ValType]):
  """Use the wire format of an already defined field type and just transform its Python value before and after parsing."""
  def __init__(self, origfield : FieldType[OriginalValType]):
    self._origfield = origfield
    
  @abstractmethod
  def transform(self, original : OriginalValType) -> ValType:
    ...
    
  @abstractmethod
  def untransform(self, transformed : ValType) -> OriginalValType:
    ...
    
  @property
  def default_value(self):
    return self.transform(self._origfield.default_value)
    
  def to_bytes(self, value):
    return self._origfield.to_bytes(self.untransform(value))
    
  def from_bytes(self, bytestr):
    val, rest = self._origfield.from_bytes(bytestr)
    return self.transform(val), rest
    
class StringField(TransformedFieldType[Optional[bytes], Optional[str]]):
  """"OPC Null string is translated to Python None."""
  
  def __init__(self):
    super().__init__(ByteStringField())
  
  def transform(self, original):
    return original.decode() if original is not None else None
    
  def untransform(self, transformed):
    return transformed.encode() if transformed is not None else None
    
class DateTimeField(TransformedFieldType[int, Optional[datetime]]):
  def __init__(self):
    super().__init__(IntField('<Q'))
  
  def transform(self, original):
    return datetime(1, 1, 1) + timedelta(milliseconds=original // 10000) if original != 0 else None
    
    
  def untransform(self, transformed):
    return round((transformed - datetime(1, 1, 1)).total_seconds() * 10000000) if transformed is not None else 0

class ArrayField(Generic[ElementType], FieldType[list[ElementType]]):
  _lenfield = IntField()
  
  def __init__(self, elfield: FieldType[ElementType]):
    self._elfield = elfield
    
  default_value = []
    
  def to_bytes(self, value):
    return self._lenfield.to_bytes(len(value)) + b''.join(self._elfield.to_bytes(el) for el in value)
    
  def from_bytes(self, bytestr):
    length, todo = self._lenfield.from_bytes(bytestr)
    result = []
    if length != 0xffffffff:
      for _ in range(0, length):
        el, todo = self._elfield.from_bytes(todo)
        result.append(el)
    return result, todo

  
class SecurityPolicyField(TransformedFieldType[Optional[str], Optional[SecurityPolicy]]):
  _prefix = 'http://opcfoundation.org/UA/SecurityPolicy#'
  
  default_value = SecurityPolicy.NONE
  
  def __init__(self):
    super().__init__(StringField())
  
  def transform(self, original):
    if original is None:
      return None
    else:
      decodecheck(original.startswith(self._prefix))
      return SecurityPolicy(original[len(self._prefix):])
    
  def untransform(self, transformed):
    return self._prefix + transformed.value if transformed is not None else None

class GuidField(TransformedFieldType[bytes, UUID]):
  def __init__(self):
    super().__init__(FixedSizeBytesField(16))
    
  def transform(self, original):
    return UUID(bytes_le=original)
    
  def untransform(self, transformed):
    return transformed.bytes_le
   
class NodeIdField(FieldType[NodeId]):
  default_value = NodeId(0,0)
  
  def to_bytes(self, value):
    # Compact representations.
    if type(value.identifier) == int:
      if value.namespace == 0 and value.identifier < 2**8:
        return struct.pack('<BB', 0, value.identifier)
      elif value.namespace < 2**8 and value.identifier < 2**16:
        return struct.pack('<BBH', 1, value.namespace, value.identifier)
        
    # Generic representations.
    enc, ft = {
      int :  (2, IntField()),
      str :  (3, StringField()),
      UUID:  (4, GuidField()),
      bytes: (5, ByteStringField()),
    }[type(value.identifier)]
    
    return bytes([enc]) + IntField('<H').to_bytes(value.namespace) + ft.to_bytes(value.identifier)
    
  def from_bytes(self, bytestr):
    enc, todo = bytestr[0], bytestr[1:]
    
    if enc == 0:
      return NodeId(namespace=0, identifier=todo[0]), todo[1:]
    elif enc == 1:
      return NodeId(*struct.unpack('<BH', todo[0:3])), todo[3:]
    else:
      decodecheck(2 <= enc <= 5)
      ft = {
        2: IntField(),
        3: StringField(),
        4: GuidField(),
        5: ByteStringField(),
      }[enc]
      namespace, todo = IntField('<H').from_bytes(todo)
      identifier, todo = ft.from_bytes(todo)
      return NodeId(namespace, identifier), todo
      
class ExpandedNodeIdField(FieldType[ExpandedNodeId]):
  default_value = ExpandedNodeId(NodeId(0,0), None, None)
  
  def to_bytes(self, value):
    basebytes = NodeIdField().to_bytes(value.nodeId)
    extramask = 0
    suffix = b''
    if value.namespaceUri is not None:
      extramask |= 0x80
      suffix += StringField().to_bytes(value.namespaceUri)
    if value.serverIndex is not None:
      extramask |= 0x40
      suffix += IntField().to_bytes(value.serverIndex)
    
    return bytes([basebytes[0] | extramask]) + basebytes[1:] + suffix

  def from_bytes(self, bytestr):
    mask, todo = bytestr[0], bytestr[1:]
    nodeId, todo = NodeIdField().from_bytes(bytes([mask & 0x0f]) + todo)
    result = ExpandedNodeId(nodeId, None, None)
    if mask & 0x80:
      result.namespaceUri, todo = StringField().from_bytes(todo)
    if mask & 0x40:
      result.serverIndex, todo = IntField().from_bytes(todo)
      
    return result, todo
      
class LocalizedTextField(FieldType[LocalizedText]):
  _strfield = StringField()
  default_value = LocalizedText()
  
  def to_bytes(self, value):
    mask = 0
    locale = b''
    text = b''
    if value.locale is not None:
      locale = self._strfield.to_bytes(value.locale)
      mask |= 0x01
    if value.text is not None:
      text = self._strfield.to_bytes(value.text)
      mask |= 0x02
    
    return bytes([mask]) + locale + text
    
  
  def from_bytes(self, bytestr):
    mask, todo = bytestr[0], bytestr[1:]
    result = LocalizedText()
    if mask & 0x01:
      result.locale, todo = self._strfield.from_bytes(todo)
    if mask & 0x02:
      result.text, todo = self._strfield.from_bytes(todo)
    
    return result, todo
    
    
class ObjectField(FieldType[NamedTuple]):
  def __init__(self, name : str, bodyfields : list[tuple[str, FieldType]]):
    self._bodyfields = bodyfields
    self._Body = namedtuple(name, [fname for fname, _ in bodyfields])
    
  def create(self, **data):
    return self._Body(**data)
    
  @property
  def default_value(self):
    return self._Body(**{fname: ftype.default_value for fname, ftype in self._bodyfields})
    
  def to_bytes(self, value):
    return b''.join(ftype.to_bytes(getattr(value, fname)) for fname, ftype in self._bodyfields)
    
  def from_bytes(self, bytestr):
    data = {}
    todo = bytestr
    for fname, ftype in self._bodyfields:
      bodyval, todo = ftype.from_bytes(todo)
      data[fname] = bodyval
    return self._Body(**data), todo
    
  @property
  def Type(self):
    return self._Body

class EncodableObjectField(ObjectField):
  def __init__(self, name : str, identifier : int, bodyfields : list[tuple[str, FieldType]]):
    super().__init__(name, [('typeId', NodeIdField()), *bodyfields])
    self._id = identifier
    self._default = super().default_value._replace(typeId=NodeId(0, identifier))
    
  def create(self, **data):
    return self._Body(typeId=NodeId(0, self._id), **data)
    
  @property
  def default_value(self):
    return self._default
    
  def from_bytes(self, bytestr):
    objectId = NodeIdField().from_bytes(bytestr)[0].identifier
    if objectId == 397 and self._id != 397:
      # Unexpected ServiceFault. Parse it into an exception.
      _, todo = NodeIdField().from_bytes(bytestr)
      _, todo = DateTimeField().from_bytes(todo)
      _, todo = IntField().from_bytes(todo)
      serviceResult, todo = IntField().from_bytes(todo)
      raise ServerError(serviceResult, f'Unexpected ServiceFault.')
    
    decodecheck(objectId == self._id, f'EncodableObjectField identifier incorrect. Expected: {self._id}; got: {objectId}')
    result, tail = super().from_bytes(bytestr)
    return result, tail

class EnumField(TransformedFieldType[int, IntEnum]):
  def __init__(self, EnumType : Type[IntEnum]):
    super().__init__(IntField())
    self._EnumType = EnumType
  
  @property
  def default_value(self):
    return next(iter(self._EnumType.__members__))
  
  def transform(self, original):
    return self._EnumType(original)
    
  def untransform(self, transformed):
    return transformed.value

class TrailingBytes(FieldType[bytes]):
  """Represents trailing bytes of a message, that may be cryptographically encoded (i.e. MAC'ed, signed or encrypted)."""
  default_value = b''
  
  def to_bytes(self, value):
    return value
    
  def from_bytes(self, bytestr):
    # Just consume everything left in the message.
    return bytestr, b''
  

class SwitchableObjectField(FieldType[NamedTuple]):
  # Object that starts with (byte-aligned) mask of which of its fields are present.
  def __init__(self, name : str, bodyfields : list[tuple[str, FieldType, int]]):
    self._fieldtypes = [(fname, ftype) for fname, ftype, _ in bodyfields]
    self._Body = namedtuple(name, [fname for fname, _, _ in bodyfields])
    self._masksize = len(bodyfields) + (8 - len(bodyfields) % 8 if len(bodyfields) % 8 else 0)
    self._maskindices = {fname: index for fname, _, index in bodyfields}
    
  @property
  def default_value(self):
    return self._Body(**{fname: None for fname, _ in self._fieldtypes})
    
  def to_bytes(self, value):
    mask = 0
    bodybytes = b''
    
    for fname, ftype in self._fieldtypes:
      element = getattr(value, fname)
      if element is not None:
        mask |= 1 << self._maskindices[fname]
        bodybytes += ftype.to_bytes(element)
      
    maskbytes = bytes(((mask >> i) % 256 for i in range(0, self._masksize, 8)))
    return maskbytes + bodybytes
    
  def from_bytes(self, bytestr):
    mask = 0
    for maskbyte in bytestr[:self._masksize // 8]:
      mask *= 256
      mask += maskbyte
    todo = bytestr[self._masksize // 8:]
    
    attributes = {}
    for fname, ftype in self._fieldtypes:
      if (mask >> self._maskindices[fname]) & 1:
        bodyval, todo = ftype.from_bytes(todo)
      else:
        bodyval = None
      
      attributes[fname] = bodyval
    
    return self._Body(**attributes), todo

class BooleanField(TransformedFieldType[int, bool]):
  def __init__(self):
    super().__init__(IntField('<B'))
  
  def transform(self, original):
    return original != 0
    
  def untransform(self, transformed):
    return 1 if transformed else 0
    
class FixedSizeBytesField(FieldType[bytes]):
  def __init__(self, size):
    self._size = size  
    
  @property
  def default_value(self):
    return b'\x00' * self._size
  
  def to_bytes(self, value):
    assert len(value) == self._size
    return value
    
  def from_bytes(self, bytestr):
    return bytestr[:self._size], bytestr[self._size:]
  
class UnsupportedField(FieldType[Any]):
  def __init__(self, name):
    def fail():
      raise UnsupportedFieldException(name, f'Field type {name} is not supported.')
    self._fail = fail
  
  @property
  def default_value(self):
    self._fail()
    
  def to_bytes(self, value):
    self._fail()
    
  def from_bytes(self, bytestr):
    self._fail()

# Extension objects. See https://reference.opcfoundation.org/Core/Part6/v104/docs/5.2.2.15
# Call register_object to expand.
class ExtensionObjectField(FieldType[Optional[NamedTuple]]):
  _id2ft = {}
  _ty2id = {}
  
  @classmethod
  def register(clazz, name : str, identifier : int, bodyfields : list[tuple[str, FieldType]]) -> FieldType:
    fieldType = ObjectField(name, bodyfields)
    assert identifier not in clazz._id2ft
    clazz._id2ft[identifier] = fieldType
    clazz._ty2id[fieldType.Type] = identifier
    return fieldType
  
  default_value = None
    
  def to_bytes(self, value):
    if value is None:
      return NodeIdField().to_bytes(NodeId(0,0)) + b'\x00'
    elif type(value) in ExtensionObjectField._ty2id:
      identifier = ExtensionObjectField._ty2id[type(value)]
      fieldType = ExtensionObjectField._id2ft[identifier]
      return NodeIdField().to_bytes(NodeId(0,identifier)) + b'\x01' + ByteStringField().to_bytes(fieldType.to_bytes(value))
    else:
      raise Exception(f'Type {type(value)} not registered as extension object.')
    
  def from_bytes(self, bytestr):
    nodeId, todo = NodeIdField().from_bytes(bytestr)
    decodecheck(nodeId.namespace == 0)
    identifier = nodeId.identifier
    decodecheck(todo)
    encoding, todo = todo[0], todo[1:]
    decodecheck(encoding != 2, 'XML encoding not supported.')
    if encoding == 0:
      bodybytes = b''
    elif encoding == 1:
      bodybytes, todo = ByteStringField().from_bytes(todo)
    else:
      decodecheck(False)
    
    if identifier == 0:
      return None, todo
    else:
      decodecheck(identifier in ExtensionObjectField._id2ft, f'Extension object type ID {identifier} not registered.')
      fieldType = ExtensionObjectField._id2ft[identifier]
      value, _ = fieldType.from_bytes(bodybytes)
      return value, todo
      
QualifiedNameField = lambda: ObjectField('QualifiedName', [
    ('namespaceIndex', IntField('<H')),
    ('name', StringField()),
  ])  
    
DataValueField = lambda: SwitchableObjectField('DataValue', [
    ('value', VariantField(), 0),
    ('statusCode', IntField(), 1),
    ('sourceTimestamp', DateTimeField(), 2),
    ('sourcePicoseconds', IntField('<H'), 4),
    ('serverTimestamp', DateTimeField(), 3),
    ('serverPicoseconds', IntField('<H'), 5),
])
    
class VariantField(FieldType[Any]):
  # Based on https://reference.opcfoundation.org/Core/Part6/v104/docs/5.1.2#_Ref131507956
  _TYPE_IDS = {
     1: BooleanField(),
     2: IntField('<b'),
     3: IntField('<B'),
     4: IntField('<h'),
     5: IntField('<H'),
     6: IntField('<l'),
     7: IntField('<L'),
     8: IntField('<q'),
     9: IntField('<Q'),
    10: DoubleField('<f'),
    11: DoubleField(),
    12: StringField(),
    13: DateTimeField(),
    14: GuidField(),
    15: ByteStringField(),
    16: UnsupportedField('XmlElement'),
    17: NodeIdField(),
    18: ExpandedNodeIdField(),
    19: IntField(),
    20: QualifiedNameField(),
    21: LocalizedTextField(),
    22: ExtensionObjectField(),
    23: None, # DataValueField(); assigned under class definition due to mutual recursion.
    24: UnsupportedField('nested Variant'),
    25: UnsupportedField('DiagnosticInfo'),
  }
  
  # Only implement a few common Python types for encoding.
  _ENCODE_TYPE_IDS = {
    bool: 1,
    int: 8,
    str: 12,
    bytes: 15
  }
  
  default_value = None
  
  def to_bytes(self, value):
    if type(value) not in VariantField._ENCODE_TYPE_IDS:
      raise Exception(f'Variant encoding of {value} not implemented.')
    identifier = VariantField._ENCODE_TYPE_IDS[type(value)]
    fieldType = VariantField._TYPE_IDS[identifier]
    return struct.pack('<B', identifier << 2) + fieldType.to_bytes(value)
    
  def from_bytes(self, bytestr):
    mask, todo = bytestr[0], bytestr[1:]
    identifier = mask & 0b00111111
    decodecheck(identifier in VariantField._TYPE_IDS)
    
    fieldType = VariantField._TYPE_IDS[identifier]
    if mask & 0b10000000:
      result, todo = ArrayField(fieldType).from_bytes(todo)
    else:
      result, todo = fieldType.from_bytes(todo)
    
    if mask & 0b01000000:
      # For now, just drop dimension info and return flattened array.
      dimensions, todo = IntField().from_bytes(todo)
      for _ in range(0, dimensions):
        _, todo = IntField().from_bytes(todo)
    
    return result, todo
    

VariantField._TYPE_IDS[24] = DataValueField()

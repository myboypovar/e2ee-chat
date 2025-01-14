import struct
from enum import IntEnum
from typing import Union

# Define constants
VERSION = 1
VERSION_SIZE = 1
PHONE_SIZE = 10
OTP_SIZE = 4  # 4 bytes for 6 digits
CODE_SIZE = 2
PAYLOAD_SIZE = 4
DH_KEY_SIZE = 32
SIGNATURE_SIZE = 512


# Enum for Request and Response Codes
class RequestCode(IntEnum):
    REQUEST_REGISTER = 825
    REQUEST_SEND_PUBLIC_KEYS = 826
    REQUEST_LOGIN = 827
    REQUEST_RECIPIENT_KEYS = 828
    REQUEST_MESSAGE = 829
    REQUEST_MESSAGE_RECEIVED = 830
    REQUEST_OTP = 831
    REQUEST_SENDER_KEYS = 832


class ResponseCode(IntEnum):
    RESPONSE_REGISTRATION = 1600
    RESPONSE_REGISTRATION_FAILED = 1601
    RESPONSE_KEYS_SET = 1602
    RESPONSE_RECIPIENT_KEYS = 1603
    RESPONSE_OTP_OK = 1604
    RESPONSE_LOGIN = 1605
    RESPONSE_LOGIN_FAILED = 1606
    RESPONSE_ERROR = 1607
    RESPONSE_MESSAGE = 1608
    RESPONSE_MESSAGE_SENT = 1609
    RESPONSE_SENDER_KEYS = 1610
    RESPONSE_LISTENING = 1611


# Define payload structures
class PublicKeys:
    """ The public keys payload """
    def __init__(self, dh_key: bytes, rsa_key: bytes):
        self.dh_key = dh_key
        self.rsa_key = rsa_key


class SignedPublicKeys:
    """ The public keys payload with signature """
    def __init__(self, dh_key: bytes, rsa_key: bytes, dh_sign: bytes, rsa_sign: bytes):
        self.dh_key = dh_key
        self.rsa_key = rsa_key
        self.dh_sign = dh_sign
        self.rsa_sign = rsa_sign


class SenderPublicKeys:
    """ The sender's public keys payload """
    def __init__(self, phone: str, dh_key: bytes, rsa_key: bytes, dh_sign: bytes, rsa_sign: bytes):
        self.dh_key = dh_key
        self.rsa_key = rsa_key
        self.dh_sign = dh_sign
        self.rsa_sign = rsa_sign
        self.phone = phone


class Phone:
    """ The recipient's phone payload """
    def __init__(self, phone: str):
        self.phone = phone


class Message:
    """ A message to be sent """
    def __init__(self, phone: str, msg: bytes):
        self.phone = phone
        self.msg = msg


class OTP:
    """ A payload that contains the OTP. """
    def __init__(self, otp_code: int):
        self.otp_code = otp_code


class EmptyPayload:
    """ Empty payload """
    pass


# Union type for Payload
Payload = Union[
    PublicKeys,
    SignedPublicKeys,
    SenderPublicKeys,
    Phone,
    Message,
    OTP,
    EmptyPayload
]


class Request:
    """
    The Request class is used to encode and decode request data.

    Attributes:
        phone (str): The phone number of the sender.
        version (int): The version of the request.
        opcode (int): The operation code of the request.
        payload_size (int): The payload size.
        payload (Payload): The dynamic payload of the request.
    """
    def __init__(self, phone: str, opcode: RequestCode, payload: Payload):
        self.phone = phone
        self.version = VERSION
        self.opcode = opcode
        self.payload_size = self.check_payload_size(payload)
        self.payload = payload

    @staticmethod
    def deserialize(data: bytes):
        """ Deserialize bytes into a Request object """
        header_size = PHONE_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE
        phone_blob, version, code, payload_size = struct.unpack(f'!{PHONE_SIZE}sBHI', data[:header_size])
        phone = phone_blob.decode('utf-8').rstrip('\x00')
        code = RequestCode(code)

        payload_data = data[header_size:]
        payload = Request.deserialize_payload(payload_data, code)
        expected_payload_size = Request.check_payload_size(payload)
        if payload_size != expected_payload_size:
            raise ValueError(f'Invalid payload size, expected: {expected_payload_size}, got: {len(payload_data)}')

        return Request(phone, code, payload)

    @staticmethod
    def deserialize_payload(payload_data: bytes, opcode: RequestCode) -> Payload:
        """ Deserialize bytes into a Request object """
        if opcode == RequestCode.REQUEST_REGISTER or opcode == RequestCode.REQUEST_LOGIN:
            return EmptyPayload()

        if opcode == RequestCode.REQUEST_OTP:
            otp = struct.unpack(f'!I', payload_data)[0]
            return OTP(otp)

        if opcode == RequestCode.REQUEST_SEND_PUBLIC_KEYS:
            dh_key = payload_data[:DH_KEY_SIZE]
            rsa_key = payload_data[DH_KEY_SIZE:]
            return PublicKeys(dh_key, rsa_key)

        if (opcode == RequestCode.REQUEST_RECIPIENT_KEYS
                or opcode == RequestCode.REQUEST_SENDER_KEYS
                or opcode == RequestCode.REQUEST_MESSAGE_RECEIVED):
            phone = struct.unpack(f'!{PHONE_SIZE}s', payload_data)[0]
            phone = phone.decode('utf-8').rstrip('\x00')
            return Phone(phone)

        if opcode == RequestCode.REQUEST_MESSAGE:
            phone = struct.unpack(f'!{PHONE_SIZE}s', payload_data[:PHONE_SIZE])[0]
            phone = phone.decode('utf-8').rstrip('\x00')
            msg = payload_data[PHONE_SIZE:]
            return Message(phone, msg)

        else:
            raise ValueError("Unknown opcode")

    @staticmethod
    def check_payload_size(payload: Payload) -> int:
        """ Returns the supposed payload size """
        if isinstance(payload, EmptyPayload):
            return 0
        elif isinstance(payload, PublicKeys):
            return len(payload.dh_key) + len(payload.rsa_key)
        elif isinstance(payload, Phone):
            return PHONE_SIZE
        elif isinstance(payload, Message):
            return PHONE_SIZE + len(payload.msg)
        elif isinstance(payload, OTP):
            return OTP_SIZE
        else:
            raise ValueError("Unknown opcode")

    def serialize(self) -> bytes:
        """ Serializes the request """
        payload_data = self.serialize_payload()
        header = struct.pack(
            f'!{PHONE_SIZE}sBHI',
            self.phone.encode('utf-8'),
            self.version,
            self.opcode,
            self.payload_size
        )
        return header + payload_data

    def serialize_payload(self) -> bytes:
        """ Serializes the request payload """
        if isinstance(self.payload, EmptyPayload):
            return b''

        if isinstance(self.payload, OTP):
            return struct.pack('!I', self.payload.otp_code)

        if isinstance(self.payload, PublicKeys):
            return self.payload.dh_key + self.payload.rsa_key

        if isinstance(self.payload, Phone):
            return struct.pack(f'!{PHONE_SIZE}s', self.payload.phone.encode('utf-8'))

        if isinstance(self.payload, Message):
            phone = self.payload.phone.encode('utf-8')
            phone_bytes = struct.pack(f'!{PHONE_SIZE}s', phone)
            return phone_bytes + self.payload.msg

        else:
            raise ValueError("Unknown payload type")


class Response:
    """
    The Response class is used to encode and decode response data.

    Attributes:
        version (int): The version of the response.
        opcode (int): The operation code of the response.
        payload_size (int): The size of the payload.
        payload (Payload): The dynamic payload of the response.
    """
    def __init__(self, opcode: ResponseCode, payload: Payload):
        self.version = VERSION
        self.opcode = opcode
        self.payload_size = self.get_payload_size(payload)
        self.payload = payload

    @staticmethod
    def get_payload_size(payload: Payload) -> int:
        """ Check the payload size """
        if isinstance(payload, EmptyPayload):
            return 0

        if isinstance(payload, OTP):
            return OTP_SIZE

        if isinstance(payload, PublicKeys):
            return len(payload.dh_key) + len(payload.rsa_key)

        if isinstance(payload, SignedPublicKeys):
            return len(payload.dh_key) + len(payload.rsa_key) + len(payload.dh_sign) + len(payload.rsa_sign)

        if isinstance(payload, SenderPublicKeys):
            return (PHONE_SIZE
                    + len(payload.dh_key)
                    + len(payload.rsa_key)
                    + len(payload.dh_sign)
                    + len(payload.rsa_sign))

        if isinstance(payload, Phone):
            return PHONE_SIZE

        if isinstance(payload, Message):
            return PHONE_SIZE + len(payload.msg)

        else:
            raise ValueError("Unknown opcode")

    def serialize(self) -> bytes:
        """ Serialize the response """
        payload_data = self.serialize_payload()
        header = struct.pack(f'!BHI',
                             self.version,
                             self.opcode,
                             self.payload_size
                             )
        return header + payload_data

    def serialize_payload(self) -> bytes:
        """ Serialize the payload """
        if isinstance(self.payload, EmptyPayload):
            return b''

        if isinstance(self.payload, OTP):
            return struct.pack(f'!I', self.payload.otp_code)

        elif isinstance(self.payload, PublicKeys):
            return self.payload.rsa_key + self.payload.dh_key

        elif isinstance(self.payload, SignedPublicKeys):
            return self.payload.dh_key + self.payload.rsa_key + self.payload.dh_sign + self.payload.rsa_sign

        elif isinstance(self.payload, SenderPublicKeys):
            phone = self.payload.phone.encode('utf-8')
            phone_bytes = struct.pack(f'!{PHONE_SIZE}s', phone)
            return (
                phone_bytes +
                self.payload.dh_key +
                self.payload.rsa_key +
                self.payload.dh_sign +
                self.payload.rsa_sign
            )

        elif isinstance(self.payload, Message):
            phone = self.payload.phone.encode('utf-8')
            msg = self.payload.msg
            phone_bytes = struct.pack(f'!{PHONE_SIZE}s', phone)
            return phone_bytes + msg

        else:
            raise ValueError("Unknown payload type")

    @staticmethod
    def deserialize(data: bytes):
        """ deserializes the response """
        header_size = VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE
        version, opcode, payload_size = struct.unpack(f'!BHI', data[:header_size])
        try:
            code = ResponseCode(opcode)
        except ValueError:
            raise ValueError(f'Invalid operation code: {opcode}')

        payload_data = data[header_size:]
        payload = Response.deserialize_payload(payload_data, code)

        return Response(code, payload)

    @staticmethod
    def deserialize_payload(payload: bytes, code: ResponseCode) -> Payload:
        """ deserializes the response payload """
        opcode = ResponseCode(code)

        if opcode == ResponseCode.RESPONSE_REGISTRATION:
            otp = struct.unpack(f'!I', payload)[0]
            return OTP(otp)

        elif opcode == ResponseCode.RESPONSE_RECIPIENT_KEYS:
            dh_key = payload[:DH_KEY_SIZE]
            rsa_key = payload[DH_KEY_SIZE:-2*SIGNATURE_SIZE]
            dh_sign = payload[-2*SIGNATURE_SIZE:-SIGNATURE_SIZE]
            rsa_sign = payload[-SIGNATURE_SIZE:]
            return SignedPublicKeys(dh_key, rsa_key, dh_sign, rsa_sign)

        elif opcode == ResponseCode.RESPONSE_SENDER_KEYS:
            phone = struct.unpack(f'!{PHONE_SIZE}s', payload[:PHONE_SIZE])[0]
            phone = phone.decode('utf-8').rstrip('\x00')
            payload = payload[PHONE_SIZE:]
            dh_key = payload[:DH_KEY_SIZE]
            rsa_key = payload[DH_KEY_SIZE:-2 * SIGNATURE_SIZE]
            dh_sign = payload[-2 * SIGNATURE_SIZE:-SIGNATURE_SIZE]
            rsa_sign = payload[-SIGNATURE_SIZE:]
            return SenderPublicKeys(phone, dh_key, rsa_key, dh_sign, rsa_sign)

        elif opcode == ResponseCode.RESPONSE_MESSAGE:
            phone = struct.unpack(f'!{PHONE_SIZE}s', payload[:PHONE_SIZE])[0]
            phone = phone.decode('utf-8').rstrip('\x00')
            msg = payload[PHONE_SIZE:]
            return Message(phone, msg)

        elif (opcode == ResponseCode.RESPONSE_LOGIN
                or opcode == ResponseCode.RESPONSE_REGISTRATION_FAILED
                or opcode == ResponseCode.RESPONSE_LOGIN_FAILED
                or opcode == ResponseCode.RESPONSE_ERROR
                or opcode == ResponseCode.RESPONSE_OTP_OK
                or opcode == ResponseCode.RESPONSE_KEYS_SET
                or opcode == ResponseCode.RESPONSE_MESSAGE_SENT
                or opcode == ResponseCode.RESPONSE_LISTENING):
            return EmptyPayload()

        else:
            raise ValueError("Unknown opcode")

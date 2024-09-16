import socket
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

from .mav_message import MAVLinkMessage, MAVLinkSerializer, MAVLinkChecksum, MAVLinkMessageCreator

# MAVLink constants
START_BYTE = 0xFE
SYSTEM_ID = 3
COMPONENT_ID = 1
SEQUENCE = 0

BUFFER_SIZE = 1024

CRC_EXTRA_CONSTANTS = {
    0: 50  # HEARTBEAT
}

STATIC_KEY = None


class MAVLinkSocket:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind((self.host, self.port))  # When connecting to PI - socket.bind(("en0", self.port))
        self.drone_ip = None
        self.drone_port = None
        self.access_control = AccessControl()

    def receive_datagram(self):
        try:
            data, addr = self.udp_socket.recvfrom(BUFFER_SIZE)
            print(f"Received data: {data} from address: {addr}, length {len(data)}")
            system_id = self.parse_system_id(data)
            if self.access_control.is_authorized(system_id):
                return data, addr
            else:
                print(f"Access denied for system ID {system_id}")
                return None, None
        except socket.error as e:
            print(f"Socket error: {e}")
            return None, None

    @staticmethod
    def parse_broadcast_id(data):
        try:
            # Decode the byte string to a normal string and strip any whitespace or newlines
            decoded_string = data.decode('utf-8').strip()

            # Convert the decoded string to an integer
            system_id = int(decoded_string)

            return system_id
        except (ValueError, TypeError) as e:
            print(f"Error parsing system ID: {e}")
            return None

    def send_datagram(self, data: bytes, target_host: str, target_port: str) -> None:
        try:
            if self.udp_socket:
                self.udp_socket.sendto(data, (target_host, target_port))
        except socket.error as e:
            print(f"Socket error: {e}")

    @staticmethod
    def get_ipaddr():
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)

    @staticmethod
    def generate_key():
        global STATIC_KEY
        key = os.urandom(32)
        STATIC_KEY = key

    def parse_system_id(self, data: bytes):
        if len(data) < 8:
            sys_id = self.parse_broadcast_id(data)
        else:
            sys_id = data[3]
        print(f"System ID: {sys_id}")
        if not self.access_control.has_authorized_ids():
            self.access_control.configure_access([sys_id])
            return sys_id
        elif self.access_control.is_authorized(sys_id):
            return sys_id
        else:
            return None


class MAVLinkRadioCommunicator:
    def __init__(self, mavlink_socket: MAVLinkSocket):
        self.mavlink_socket = mavlink_socket

    @staticmethod
    def receive_message(data):
        if len(data) < 8:
            print("Invalid packet length")
            return

        start_byte, length, sequence, system_id, component_id, msg_id = struct.unpack('<BBBBBB', data[:6])

        if start_byte == START_BYTE:
            print(f"Bytes Received: {len(data)}")

            hex_string = ' '.join(format(byte, '02x') for byte in data)
            print(f"Datagram: {hex_string}")

            mav_message = MAVLinkMessageCreator().create_message(msg_id)

            if mav_message is None:
                print("Message ID not recognized")
                return

            received_payload = data[6:6 + length]
            # Decrypt message
            if length > 10:  # if length is greater than 10 for now, it means that the message is encrypted
                decryptor = MAVLinkSec(STATIC_KEY)
                received_payload = decryptor.decrypt_chacha20(data[6:6 + length])

            serializer = MAVLinkSerializer(mav_message)
            payload = serializer.deserialize(received_payload)
            received_checksum = data[6 + length]

            crc_extra = CRC_EXTRA_CONSTANTS.get(msg_id, 0)
            checksum_data = data[1:6 + length]
            computed_checksum = MAVLinkChecksum().compute(checksum_data, crc_extra)

            if received_checksum == computed_checksum:
                print(f"Received packet: SYS: {system_id}, COMP: {component_id}, LEN: {length}, MSG ID: {msg_id}, "
                      f"Payload: {payload}")
                return
            else:
                print(f"Invalid checksum: received {received_checksum}, computed {computed_checksum}")
                return
        else:
            print("Invalid MAVLink message start byte")
            return None

    def share_static_key(self, target_host, target_port):
        identifier = b'\x01'
        preshared_key = identifier + STATIC_KEY
        self.mavlink_socket.send_datagram(preshared_key, target_host, target_port)
        print(f"Share static key: {preshared_key}")

    def send_message(self, message: MAVLinkMessage, values: dict, target_host, target_port, encrypted) -> None:
        serializer = MAVLinkSerializer(message)
        payload = serializer.serialize(values)

        mav_message = payload

        if encrypted:
            # Encrypt message
            encryptor = MAVLinkSec(STATIC_KEY)
            mav_message = encryptor.encrypt_chacha20(payload)

        # Packet creation
        length = len(mav_message)
        msg_id = message.message_id
        header = struct.pack('<BBBBBB', START_BYTE, length, SEQUENCE, SYSTEM_ID, COMPONENT_ID, msg_id)

        # Compute Checksum
        crc_extra = CRC_EXTRA_CONSTANTS.get(msg_id, 0)
        checksum = MAVLinkChecksum().compute(header[1:] + mav_message, crc_extra)
        checksum_bytes = struct.pack('<H', checksum)

        mavlink_packet = header + mav_message + checksum_bytes

        print("Bytes Sent:", len(mavlink_packet))

        hex_string = ' '.join(format(byte, '02x') for byte in mavlink_packet)
        print("Datagram:", hex_string)

        print(f"Sent packet: SYS: {header[3]}, COMP: {header[4]}, LEN: {length}, MSG ID: {msg_id}, "
              f"Payload: {payload}")

        self.mavlink_socket.send_datagram(mavlink_packet, target_host, target_port)


class AccessControl:
    def __init__(self):
        self.authorized_system_ids = set()

    def configure_access(self, system_ids: list[int]):
        print(f"list uploaded: {system_ids}")

        self.authorized_system_ids.update(system_ids)

    def is_authorized(self, system_id: int) -> bool:
        return system_id in self.authorized_system_ids

    def has_authorized_ids(self) -> bool:
        return len(self.authorized_system_ids) > 0


class MAVLinkSec:
    def __init__(self, key=STATIC_KEY):
        self.key = key

    def encrypt_chacha20(self, payload):
        nonce = os.urandom(16)

        algorithm = algorithms.ChaCha20(self.key, nonce)
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(payload)

        return nonce + ciphertext

    def decrypt_chacha20(self, encrypted_message):
        nonce = encrypted_message[:16]
        ciphertext = encrypted_message[16:]

        algorithm = algorithms.ChaCha20(self.key, nonce)
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(ciphertext)

        return decrypted_message

    def aes_encrypt(self, payload):
        nonce = os.urandom(16)

        algorithm = algorithms.AES(self.key)
        cipher = Cipher(algorithm, modes.CTR(nonce), backend=default_backend())

        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(payload) + encryptor.finalize()

        return nonce + ciphertext

    def aes_decrypt(self, cipher_message):
        nonce = cipher_message[:16]
        encrypted_message = cipher_message[16:]

        algorithm = algorithms.AES(self.key)
        cipher = Cipher(algorithm, modes.CTR(nonce), backend=default_backend())

        decrypt = cipher.decryptor()
        decrypted_message = decrypt.update(encrypted_message) + decrypt.finalize()

        return decrypted_message

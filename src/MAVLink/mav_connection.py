import socket
import struct
from typing import Optional

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


class MAVLinkSocket:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind((self.host, self.port))  # When connecting to PI ~ socket.bind(("en0", self.port))
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

            serializer = MAVLinkSerializer(mav_message)
            payload = serializer.deserialize(data[6:6 + length])
            received_checksum = data[6 + length]

            crc_extra = CRC_EXTRA_CONSTANTS.get(msg_id, 0)
            computed_checksum = MAVLinkChecksum.compute(data[1:6 + length], crc_extra)

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

    def send_message(self, message: MAVLinkMessage, values: dict, target_host, target_port) -> None:
        serializer = MAVLinkSerializer(message)
        payload = serializer.serialize(values)

        # packet creation
        length = len(payload)
        msg_id = message.message_id
        header = struct.pack('<BBBBBB', START_BYTE, length, SEQUENCE, SYSTEM_ID, COMPONENT_ID, msg_id)

        # Compute Checksum
        crc_extra = CRC_EXTRA_CONSTANTS.get(msg_id, 0)
        checksum = MAVLinkChecksum.compute(header[1:] + payload, crc_extra)
        checksum_bytes = struct.pack('<H', checksum)

        mavlink_packet = header + payload + checksum_bytes

        print("Bytes Sent:", len(mavlink_packet))

        hex_string = ' '.join(format(byte, '02x') for byte in mavlink_packet)
        print("Datagram:", hex_string)

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
    def __init__(self):
        self.algo = None


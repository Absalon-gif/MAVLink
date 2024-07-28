from .mav_message import MAVLinkMessage, MAVLinkSerializer, MAVLinkChecksum
import socket
import struct


# MAVLink constants
START_BYTE = 0xFE
SYSTEM_ID = 3
COMPONENT_ID = 1
SEQUENCE = 0

BUFFER_SIZE = 1024


class MAVLinkSocket:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind((self.host, self.port))
        self.drone_ip = None
        self.drone_port = None

    def receive_datagram(self):
        try:
            data, addr = self.udp_socket.recvfrom(BUFFER_SIZE)
            return data.decode(), addr
        except socket.error as e:
            print(f"Socket error: {e}")
            return None, None

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


class MAVLinkRadioCommunicator:
    def __init__(self, mavlink_socket: MAVLinkSocket):
        self.mavlink_socket = mavlink_socket

    def send_message(self, message: MAVLinkMessage, values: dict, target_host, target_port) -> None:
        serializer = MAVLinkSerializer(message)
        payload = serializer.serialize(values)

        # packet creation
        length = len(payload)
        msg_id = message.message_id
        header = struct.pack('<BBBBBB', START_BYTE, length, SEQUENCE, SYSTEM_ID, COMPONENT_ID, msg_id)

        # Compute Checksum
        checksum = MAVLinkChecksum(message).compute(header[1:] + payload)
        checksum_bytes = struct.pack('<B', checksum)

        mavlink_packet = header + payload + checksum_bytes

        print("Bytes Sent:", len(mavlink_packet))

        hex_string = ' '.join(format(byte, '02x') for byte in mavlink_packet)
        print("Datagram:", hex_string)

        self.mavlink_socket.send_datagram(mavlink_packet, target_host, target_port)

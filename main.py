import sys
import subprocess
import time
from PyQt5.QtWidgets import QApplication, QLineEdit,QMainWindow, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel, QMessageBox
from src.MAVLink.mav_message import MAVLinkXMLParser
from src.MAVLink.mav_connection import MAVLinkSocket, MAVLinkRadioCommunicator

prelim_values = {
    'type': 0,  # MAV_TYPE: Generic micro air vehicle
    'autopilot': 1,  # MAV_AUTOPILOT: Reserved for future use.
    'base_mode': 0,  # MAV_MODE_FLAG: (Bitmask) These flags encode the MAV mode.
    'custom_mode': 0,  # A bitfield for use for autopilot-specific flags
    'system_status': 0,  # MAV_STATE: System status flag.
    'mavlink_version': 3  # MAVLink version
}

parser = MAVLinkXMLParser()
messages = parser.parse_file('message_definitions/common.xml')

heartbeat_message = next(message for message in messages if message.message_id == 0)


class AccessControl:
    def __init__(self):
        self.authorized_system_ids = set()

    def configure_access(self, system_ids: list[int]):
        self.authorized_system_ids.update(system_ids)

    def is_authorized(self, system_id: int) -> bool:
        return system_id in self.authorized_system_ids


class GCSApp(QMainWindow):
    def __init__(self, mav_socket):
        super().__init__()

        self.mav_socket = mav_socket
        self.mav_communicator = MAVLinkRadioCommunicator(mav_socket)
        self.access_control = AccessControl()

        self.initUI()
        self.listen_broadcast = True

    def initUI(self):
        self.setWindowTitle('GCS - Ground Control Station')
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout(central_widget)

        self.title_label = QLabel('GCS Application', self)
        self.title_label.setStyleSheet("font-size: 16pt; font-weight: bold;")
        layout.addWidget(self.title_label)

        self.ssid_input = QLineEdit(self)
        self.ssid_input.setPlaceholderText("Enter Drone's SSID")
        layout.addWidget(self.ssid_input)

        self.connect_button = QPushButton('Connect to Drone', self)
        self.connect_button.clicked.connect(self.connect_to_drone)
        layout.addWidget(self.connect_button)

        self.drone_info_label = QLabel('Drone not discovered yet', self)
        layout.addWidget(self.drone_info_label)

        self.send_heartbeat_button = QPushButton('Send Heartbeat Message', self)
        self.send_heartbeat_button.clicked.connect(self.send_heartbeat)
        layout.addWidget(self.send_heartbeat_button)

        self.logs_text = QTextEdit(self)
        self.logs_text.setReadOnly(True)
        layout.addWidget(self.logs_text)

        self.show()

    def log(self, message):
        self.logs_text.append(message)

    def connect_to_drone(self):
        ssid = self.ssid_input.text()
        if ssid:
            self.logs_text.append(f"Attempting to connect to Drone with SSID: {ssid}")
            # Turn Wi-Fi off
            subprocess.run(["networksetup", "-setairportpower", "en0", "off"])
            time.sleep(1)

            # Turn Wi-Fi on
            subprocess.run(["networksetup", "-setairportpower", "en0", "on"])
            time.sleep(1)

            # Connect to the hidden SSID
            subprocess.run(["networksetup", "-setairportnetwork", "en0", ssid])
            time.sleep(5)

            connection_status = subprocess.run(["networksetup", "-getairportnetwork", "en0"], capture_output=True, text=True)
            if ssid in connection_status.stdout:
                print(f"Successfully connected to {ssid}")
            else:
                print(f"Failed to connect to {ssid}")

    def receive_broadcasts(self):
        while self.listen_broadcast:
            try:
                data, (drone_ip, drone_port) = self.mav_socket.receive_broadcast()
                if drone_ip and drone_port:
                    self.mav_socket.drone_ip = drone_ip
                    self.mav_socket.drone_port = drone_port
                    self.access_control.configure_access(data)
                    print(f"Discovered drone at {drone_ip}:{drone_port}, with SYS_ID: {data}")
                    self.send_heartbeat()
                    self.log(f"Discovered drone at {drone_ip}:{drone_port}, with SYS_ID: {data}")
                    self.update_drone_info(drone_ip, drone_port, data)
                    self.listen_broadcast = False
                    break
            except Exception as e:
                print(f"Error receiving broadcast: {e}")
                self.log(f"Error receiving broadcast: {e}")

    def update_drone_info(self, drone_ip, drone_port, data):
        print(f"Updating drone info: {drone_ip}:{drone_port}, with SYS_ID: {data}")
        self.log(f"Discovered drone at {drone_ip}:{drone_port}, with SYS_ID: {data}")
        self.drone_info_label.setText(f"Discovered drone at {drone_ip}:{drone_port}")
        self.log(f"Updated drone info: {drone_ip}:{drone_port}, with SYS_ID: {data}")

    def send_heartbeat(self):
        try:
            self.mav_communicator.send_message(heartbeat_message, prelim_values,
                                               self.mav_socket.drone_ip, self.mav_socket.drone_port)
            self.log("Heartbeat message sent")
            QMessageBox.information(self, "Info", "Heartbeat message sent")
        except Exception as e:
            self.log(f"Failed to send heartbeat message: {e}")
            QMessageBox.critical(self, "Error", f"Failed to send heartbeat message: {e}")


if __name__ == "__main__":
    mavlink_socket = MAVLinkSocket('0.0.0.0', 50001)
    app = QApplication(sys.argv)
    ex = GCSApp(mavlink_socket)
    sys.exit(app.exec_())

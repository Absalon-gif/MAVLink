import sys
import subprocess
import time
import threading
from PyQt5.QtCore import pyqtSignal, QObject
from PyQt5.QtWidgets import QApplication, QLineEdit, QMainWindow, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel, \
    QMessageBox, QCheckBox, QHBoxLayout
from src.MAVLink.mav_connection import MAVLinkSocket, MAVLinkRadioCommunicator, AccessControl
from src.MAVLink.mav_message import MAVLinkMessageCreator


heartbeat_values = {
    'type': 0,
    'autopilot': 1,
    'base_mode': 0,
    'custom_mode': 0,
    'system_status': 0,
    'mavlink_version': 3
}

status_values = {
    'onboard_control_sensors_health': 1,
    'load': 500,
    'current_battery': 30,
    'battery_remaining': 45
}

home_position_values = {
    'latitude': 1,
    'longitude': 500,
    'altitude': 30,
}


class WorkerSignals(QObject):
    log = pyqtSignal(str)
    update_drone_info = pyqtSignal(str, str, str)
    heartbeat_sent = pyqtSignal()


class GCSApp(QMainWindow):
    def __init__(self, mav_socket):
        super().__init__()

        self.mav_socket = mav_socket
        self.mav_communicator = MAVLinkRadioCommunicator(mav_socket)
        self.listen_broadcast = True
        self.listen_thread = None
        self.encrypted = None

        # Set up signals
        self.signals = WorkerSignals()

        # Connect signals to slots
        self.signals.log.connect(self.log)
        self.signals.update_drone_info.connect(self.update_drone_info)
        self.signals.heartbeat_sent.connect(self.handle_heartbeat_sent)

        self.initUI()

    def initUI(self):
        self.setWindowTitle('GCS - Ground Control Station')
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout(central_widget)

        self.title_label = QLabel('GCS Application', self)
        self.title_label.setStyleSheet("font-size: 16pt; font-weight: bold;")
        layout.addWidget(self.title_label)

        # Drone SSID Input
        self.ssid_input = QLineEdit(self)
        self.ssid_input.setPlaceholderText("Enter Drone's SSID")
        layout.addWidget(self.ssid_input)

        # Buttons
        self.connect_button = QPushButton('Connect to Drone', self)
        self.connect_button.clicked.connect(self.connect_to_drone)
        layout.addWidget(self.connect_button)

        self.receive_button = QPushButton('Receive Broadcast', self)
        self.receive_button.clicked.connect(self.start_listening_thread)
        layout.addWidget(self.receive_button)

        # Drone Info Label
        self.drone_info_label = QLabel('Drone not discovered yet', self)
        layout.addWidget(self.drone_info_label)

        # Heartbeat Buttons
        self.send_heartbeat_button = QPushButton('Send Heartbeat Message', self)
        self.send_heartbeat_button.clicked.connect(self.send_heartbeat)
        layout.addWidget(self.send_heartbeat_button)

        self.send_multiple_heartbeat_button = QPushButton('Send Multiple Heartbeats', self)
        self.send_multiple_heartbeat_button.clicked.connect(self.send_multiple_heartbeats)
        layout.addWidget(self.send_multiple_heartbeat_button)

        self.iterations_input = QLineEdit(self)
        self.iterations_input.setPlaceholderText("Enter number of iterations")
        layout.addWidget(self.iterations_input)

        # Encrypted/Unencrypted Option Flag
        self.encryption_checkbox = QCheckBox("Send Encrypted", self)
        layout.addWidget(self.encryption_checkbox)

        # Horizontal layout for logs and time display
        h_layout = QHBoxLayout()

        # Communication Logs Textbox
        self.logs_text = QTextEdit(self)
        self.logs_text.setReadOnly(True)
        h_layout.addWidget(self.logs_text)

        # Average Time Textbox
        self.time_text = QTextEdit(self)
        self.time_text.setReadOnly(True)
        h_layout.addWidget(self.time_text)

        layout.addLayout(h_layout)

        self.show()

    def log(self, message):
        self.logs_text.append(message)

    def connect_to_drone(self):
        ssid = self.ssid_input.text()
        if ssid:
            self.signals.log.emit(f"Attempting to connect to Drone with SSID: {ssid}")
            subprocess.run(["networksetup", "-setairportpower", "en0", "off"])
            time.sleep(1)
            subprocess.run(["networksetup", "-setairportpower", "en0", "on"])
            time.sleep(1)
            subprocess.run(["networksetup", "-setairportnetwork", "en0", ssid])
            time.sleep(5)
            connection_status = subprocess.run(["networksetup", "-getairportnetwork", "en0"], capture_output=True,
                                               text=True)
            if ssid in connection_status.stdout:
                self.signals.log.emit(f"Connected to Drone with SSID: {ssid}")
                self.start_listening_thread()
            else:
                self.signals.log.emit(f"Failed to connect to {ssid}")

    def start_listening_thread(self):
        if self.listen_thread is None or not self.listen_thread.is_alive():
            self.listen_thread = threading.Thread(target=self.listen_for_datagrams)
            self.listen_thread.start()

    def listen_for_datagrams(self):
        while True:
            try:
                data, (drone_ip, drone_port) = self.mav_socket.receive_datagram()
                if drone_ip and drone_port:
                    if self.listen_broadcast is False:
                        self.mav_communicator.receive_message(data)
                    if not self.mav_socket.drone_ip and not self.mav_socket.drone_port:
                        self.mav_socket.drone_ip = drone_ip
                        self.mav_socket.drone_port = drone_port
                        self.mav_socket.host = MAVLinkSocket.get_ipaddr()
                        self.is_encrypted()
                        print(f"Discovered drone at {drone_ip}:{drone_port}, with SYS_ID: {data}")
                        self.send_heartbeat()
                        self.signals.log.emit(f"Discovered drone at {drone_ip}:{drone_port}, with SYS_ID: {data}")
                        self.update_drone_info(drone_ip, drone_port, data)
                        self.listen_broadcast = False
            except Exception as e:
                self.signals.log.emit(f"Error receiving datagram: {e}")

    def is_encrypted(self):
        self.encrypted = self.encryption_checkbox.isChecked()
        if self.encrypted:
            # Generate the static key to share
            MAVLinkSocket.generate_key()
            # Share the static key with the Drone
            self.mav_communicator.share_static_key(self.mav_socket.drone_ip, self.mav_socket.drone_port)
            return True
        else:
            return False

    def update_drone_info(self, drone_ip, drone_port, data):
        print(f"Updating drone info: {drone_ip}:{drone_port}, with SYS_ID: {data}")
        self.signals.log.emit(f"Discovered drone at {drone_ip}:{drone_port}, with SYS_ID: {data}")
        self.drone_info_label.setText(f"Discovered drone at {drone_ip}:{drone_port}")
        self.signals.log.emit(f"Updated drone info: {drone_ip}:{drone_port}, with SYS_ID: {data}")

    def send_heartbeat(self):
        mav_message = MAVLinkMessageCreator().create_message(0)
        try:
            if self.encrypted:
                self.mav_communicator.send_message(mav_message, heartbeat_values,
                                                   self.mav_socket.drone_ip, self.mav_socket.drone_port, True)
            else:
                self.mav_communicator.send_message(mav_message, heartbeat_values,
                                                   self.mav_socket.drone_ip, self.mav_socket.drone_port, False)
            self.signals.log.emit("Heartbeat message sent")
            self.signals.heartbeat_sent.emit()
        except Exception as e:
            self.signals.log.emit(f"Failed to send heartbeat message: {e}")

    def send_multiple_heartbeats(self):
        iterations = int(self.iterations_input.text())
        start_time = time.perf_counter()
        mav_message = MAVLinkMessageCreator().create_message(0)
        for _ in range(iterations):
            try:
                if self.encrypted:
                    self.mav_communicator.send_message(mav_message, heartbeat_values,
                                                       self.mav_socket.drone_ip, self.mav_socket.drone_port, True)
                else:
                    self.mav_communicator.send_message(mav_message, heartbeat_values,
                                                       self.mav_socket.drone_ip, self.mav_socket.drone_port, False)
            except Exception as e:
                self.time_text.append(f"Failed to send heartbeat message: {e}")

        end_time = time.perf_counter()
        total_time = end_time - start_time
        avg_time_per_packet = total_time / iterations
        if self.encrypted:
            print(f"Total time for {iterations} encrypted packets: {total_time:.6f} seconds")
            self.time_text.append(f"Total time for {iterations} encrypted packets: {total_time:.6f} seconds")
            print(f"Average time per encrypted packet: {avg_time_per_packet:.6f} seconds")
            self.time_text.append(f"Average time per encrypted packet: {avg_time_per_packet:.6f} seconds")
        else:
            print(f"Total time for {iterations} unencrypted packets: {total_time:.6f} seconds")
            self.time_text.append(f"Total time for {iterations} unencrypted packets: {total_time:.6f} seconds")
            print(f"Average time per unencrypted packet: {avg_time_per_packet:.6f} seconds")
            self.time_text.append(f"Average time per unencrypted packet: {avg_time_per_packet:.6f} seconds")

    def handle_heartbeat_sent(self):
        QMessageBox.information(self, "Info", "Heartbeat message sent")


if __name__ == "__main__":
    mavlink_socket = MAVLinkSocket('0.0.0.0', 50001)
    app = QApplication(sys.argv)
    ex = GCSApp(mavlink_socket)
    sys.exit(app.exec_())

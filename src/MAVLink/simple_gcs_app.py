import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, QTextEdit

class SimpleApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle('Simple PyQt5 App')

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout(central_widget)

        self.log_button = QPushButton('Log Message', self)
        self.log_button.clicked.connect(self.log_message)
        layout.addWidget(self.log_button)

        self.logs_text = QTextEdit(self)
        self.logs_text.setReadOnly(True)
        layout.addWidget(self.logs_text)

        self.show()

    def log_message(self):
        self.logs_text.append("Button clicked, logging a message!")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = SimpleApp()
    sys.exit(app.exec_())

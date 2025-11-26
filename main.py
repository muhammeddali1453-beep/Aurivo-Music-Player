# main.py
import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel
from PyQt5.QtCore import Qt

class AngollaPlayer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Angolla Music Player - Initial Draft")
        self.setGeometry(100, 100, 800, 600)  # Pencere Boyutu

        # Pencere içine bir etiket ekleyelim
        self.label = QLabel("Angolla Music Player Kodlaması Başladı!", self)
        self.label.setAlignment(Qt.AlignCenter)
        self.setCentralWidget(self.label)

def main():
    app = QApplication(sys.argv)
    window = AngollaPlayer()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()

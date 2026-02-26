import sys
import os
sys.path.insert(0, os.path.abspath('src'))
from gui.main_window import MainWindow
def main():
    app = MainWindow()
    app.run()
if __name__ == "__main__":
    main()
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
try:
    from gui.main_window import MainWindow
except ImportError as e:
    print(f"Ошибка импорта: {e}")
    print(f"Текущий путь: {sys.path}")
    sys.exit(1)
def main():
    app = MainWindow()
    app.run()
if __name__ == "__main__":
    main()
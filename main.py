"""
Главный entry point приложения
"""

import sys
import os

# Добавляем путь к проекту
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from slr_checker.gui import main

if __name__ == "__main__":
    main()

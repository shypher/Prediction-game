import os
from pathlib import Path

IGNORE = {"__pycache__"}  

def print_tree(start_path: Path, prefix: str = ""):
    entries = sorted(e for e in os.listdir(start_path) if e not in IGNORE)
    for index, name in enumerate(entries):
        path = start_path / name
        connector = "├── " if index < len(entries) - 1 else "└── "
        print(prefix + connector + name)
        if path.is_dir():
            extension = "│   " if index < len(entries) - 1 else "    "
            print_tree(path, prefix + extension)

if __name__ == "__main__":
    base = Path(__file__).resolve().parents[2]  # backend
    print(f"Project tree for: {base}\n")
    print_tree(base)
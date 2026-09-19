import os

# Folders to scan (in order)
ROOT_DIRS = ['myground', 'security', 'authentication']

# Directory names to exclude anywhere in the tree
EXCLUDE_DIRS = {'__pycache__', 'migrations', 'utils'}

output = []

def is_excluded(path):
    """Return True if any path segment is in EXCLUDE_DIRS."""
    parts = os.path.normpath(path).split(os.sep)
    return any(part in EXCLUDE_DIRS for part in parts)

def walk_project(root_dir):
    """Yield (root, files) tuples, pruning excluded dirs."""
    if not os.path.isdir(root_dir):
        return
    for root, dirs, files in os.walk(root_dir):
        # Prune excluded directories in-place so os.walk doesn't descend into them
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        if is_excluded(root):
            continue
        yield root, files

# ---------------------------------------------------------------
# 1. Directory structure
# ---------------------------------------------------------------
output.append("=" * 80)
output.append("DIRECTORY STRUCTURE")
output.append("=" * 80)

for root_dir in ROOT_DIRS:
    if not os.path.isdir(root_dir):
        output.append(f"[WARNING: '{root_dir}' does not exist — skipped]")
        continue
    for root, files in walk_project(root_dir):
        for file in files:
            output.append(os.path.join(root, file))

# ---------------------------------------------------------------
# 2. Python file contents
# ---------------------------------------------------------------
output.append("\n")
output.append("=" * 80)
output.append("PYTHON FILE CONTENTS")
output.append("=" * 80)

for root_dir in ROOT_DIRS:
    if not os.path.isdir(root_dir):
        continue
    for root, files in walk_project(root_dir):
        for file in files:
            if not file.endswith('.py'):
                continue

            filepath = os.path.join(root, file)

            output.append("\n" + "=" * 80)
            output.append(f"FOLDER: {root}")
            output.append(f"FILE NAME: {file}")
            output.append(f"FULL PATH: {filepath}")
            output.append("=" * 80)
            output.append("")

            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    output.append(f.read())
            except Exception as e:
                output.append(f"[ERROR: Could not read file - {e}]")

# ---------------------------------------------------------------
# 3. Write output
# ---------------------------------------------------------------
with open('output.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(output))

print("Done! Check output.txt")
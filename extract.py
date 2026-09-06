import os

exclude_dirs = ['__pycache__', 'migrations', 'utils']
output = []

# Directory structure
output.append("=" * 80)
output.append("DIRECTORY STRUCTURE")
output.append("=" * 80)

# Walk through myground
for root, dirs, files in os.walk('myground'):
    dirs[:] = [d for d in dirs if d not in exclude_dirs]
    for file in files:
        skip = False
        for excl in exclude_dirs:
            if excl in root:
                skip = True
                break
        if not skip:
            output.append(os.path.join(root, file))

# Walk through security
for root, dirs, files in os.walk('security'):
    dirs[:] = [d for d in dirs if d not in exclude_dirs]
    for file in files:
        skip = False
        for excl in exclude_dirs:
            if excl in root:
                skip = True
                break
        if not skip:
            output.append(os.path.join(root, file))

output.append("\n")
output.append("=" * 80)
output.append("PYTHON FILE CONTENTS")
output.append("=" * 80)

# Process myground Python files
for root, dirs, files in os.walk('myground'):
    dirs[:] = [d for d in dirs if d not in exclude_dirs]
    
    skip = False
    for excl in exclude_dirs:
        if excl in root:
            skip = True
            break
    if skip:
        continue
        
    for file in files:
        if file.endswith('.py'):
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

# Process security Python files
for root, dirs, files in os.walk('security'):
    dirs[:] = [d for d in dirs if d not in exclude_dirs]
    
    skip = False
    for excl in exclude_dirs:
        if excl in root:
            skip = True
            break
    if skip:
        continue
        
    for file in files:
        if file.endswith('.py'):
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

# Write everything to output.txt
with open('output.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(output))

print("Done! Check output.txt")
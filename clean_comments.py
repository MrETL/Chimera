"""Remove AI/development comments from all Python files."""
import glob, re

files = (
    glob.glob('chimera/**/*.py', recursive=True)
)
files = [f for f in files if '__pycache__' not in f]

# Patterns to remove
REMOVE_PATTERNS = [
    # Lines that reference other tools
    r'.*[Mm]etasploit.*\n',
    r'.*[Pp]y[Rr][Ii][Tt].*\n',
    r'.*[Hh]arm[Bb]ench.*\n',
    r'.*[Tt]encent.*\n',
    r'.*[Mm]icrosoft.*\n',
    r'.*[Aa]nthropic.*2024.*\n',
    # Lines with "Based on:" references to papers
    r'\s*#\s*[Bb]ased on:.*\n',
    r'\s*#\s*[Rr]eference:.*\n',
    r'\s*#\s*[Rr]ef:.*\n',
    # Lines with "Phase" development notes
    r'\s*#.*[Pp]hase \d.*\n',
    r'\s*#.*[Nn]ew dependencies.*\n',
    # Overly verbose section dividers
    r'\s*# ──+.*\n',
    r'\s*# ==+.*\n',
    # "Register" comments
    r'\s*# [Rr]egister.*[Tt]arget[Mm]anager.*\n',
    r'\s*# [Rr]egister with.*\n',
    r'\s*# [Rr]egister all.*\n',
    # "Lazy import" comments
    r'\s*# .*imported lazily.*\n',
    r'\s*# .*lazy import.*\n',
    r'\s*# .*import lazily.*\n',
    # torch/deap placeholder comments
    r'\s*# torch.*lazily.*\n',
    r'\s*# deap.*lazily.*\n',
    r'\s*# PIL.*lazily.*\n',
    r'\s*# numpy.*lazily.*\n',
    # "TODO" and "FIXME" in non-attack content
    r'\s*# TODO:.*\n',
    r'\s*# FIXME:.*\n',
    # Verbose module docstrings that mention "Phase"
]

cleaned = 0
for fpath in files:
    with open(fpath) as f:
        content = f.read()
    original = content
    
    for pattern in REMOVE_PATTERNS:
        content = re.sub(pattern, '', content)
    
    # Clean up multiple blank lines (max 1)
    content = re.sub(r'\n{3,}', '\n\n', content)
    
    if content != original:
        with open(fpath, 'w') as f:
            f.write(content)
        cleaned += 1

print(f'cleaned: {cleaned} files')

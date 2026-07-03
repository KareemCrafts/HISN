with open('src/dashboard/app.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Show lines 1815-1835 with visible tab markers
for i, line in enumerate(lines[1814:1835], start=1815):
    visible = line.replace('\t', '>>TAB<<').replace(' ', '·')
    print(f"{i}: {visible}", end='')
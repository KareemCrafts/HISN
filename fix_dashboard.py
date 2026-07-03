with open('src/dashboard/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

target = 'def dashboard():\n'
replacement = 'def dashboard():\n    global_context_str = ""\n'

if 'global_context_str = ""' in content:
    print("Already present — no change needed.")
elif target in content:
    content = content.replace(target, replacement, 1)
    with open('src/dashboard/app.py', 'w', encoding='utf-8', newline='\n') as f:
        f.write(content)
    print("Fixed — global_context_str added.")
else:
    print("ERROR: could not find def dashboard() — check the file.")
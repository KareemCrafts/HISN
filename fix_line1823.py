with open('src/dashboard/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

bad = '    with Session(engine) as session:        incidents = session.query(Incident).all()'
good = '    with Session(engine) as session:\n        incidents = session.query(Incident).all()'

if bad in content:
    content = content.replace(bad, good, 1)
    with open('src/dashboard/app.py', 'w', encoding='utf-8', newline='\n') as f:
        f.write(content)
    print("Fixed line 1823.")
else:
    # try with tabs mixed in
    import re
    pattern = r'    with Session\(engine\) as session:\s+incidents = session\.query\(Incident\)\.all\(\)'
    replacement = '    with Session(engine) as session:\n        incidents = session.query(Incident).all()'
    new_content, count = re.subn(pattern, replacement, content)
    if count:
        with open('src/dashboard/app.py', 'w', encoding='utf-8', newline='\n') as f:
            f.write(new_content)
        print(f"Fixed via regex ({count} replacement).")
    else:
        print("ERROR: pattern not found. Paste check_line.py output.")
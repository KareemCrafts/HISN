with open('src/dashboard/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Update route to use parse_file dispatcher
old_route = '''@app.route("/scan-email", methods=["POST"])
def scan_email_route():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "Please choose a file."}), 400
    if not f.filename.lower().endswith(".eml"):
        return jsonify({"error": "Unsupported file type. Upload a .eml file."}), 400
    path = os.path.join(DOC_UPLOAD_DIR, secure_filename(f.filename))
    f.save(path)
    from src.parsers.email_parser import parse_email_file
    result = parse_email_file(path)
    return jsonify(result)'''

new_route = '''@app.route("/scan-email", methods=["POST"])
def scan_email_route():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "Please choose a file."}), 400
    allowed_exts = ('.eml', '.msg', '.png', '.jpg', '.jpeg', '.webp', '.bmp', '.gif', '.tiff', '.tif')
    if not f.filename.lower().endswith(allowed_exts):
        return jsonify({"error": "Unsupported file type. Upload .eml, .msg, or a screenshot (.png, .jpg, etc)."}), 400
    path = os.path.join(DOC_UPLOAD_DIR, secure_filename(f.filename))
    f.save(path)
    from src.parsers.email_parser import parse_file
    result = parse_file(path)
    return jsonify(result)'''

if old_route in content:
    content = content.replace(old_route, new_route, 1)
    print("OK: route updated")
else:
    print("MISS: route not found exactly — trying partial match")
    import re
    pat = re.compile(r'@app\.route\("/scan-email".*?return jsonify\(result\)', re.DOTALL)
    content, n = pat.subn(new_route, content, 1)
    print(f"Partial match: {n} replacement(s)")

# 2. Update file input accept attribute
old_fi = 'accept=".eml" style="display:none;"'
new_fi = 'accept=".eml,.msg,.png,.jpg,.jpeg,.webp,.bmp,.gif,.tiff" style="display:none;"'
if old_fi in content:
    content = content.replace(old_fi, new_fi, 1)
    print("OK: file input accept updated")
else:
    print("MISS: file input accept not found")

# 3. Update browse button label
old_btn = '>Choose .eml File<'
new_btn = '>Choose Email or Screenshot<'
if old_btn in content:
    content = content.replace(old_btn, new_btn, 1)
    print("OK: button label updated")
else:
    print("MISS: button label not found")

# 4. Update the JS file type check
old_js = "if (!file.name.toLowerCase().endsWith('.eml')) { per.textContent='Please choose a .eml file.'; return; }"
new_js = ("var pext = file.name.split('.').pop().toLowerCase();\n"
          "      var pallowed = ['eml','msg','png','jpg','jpeg','webp','bmp','gif','tiff','tif'];\n"
          "      if (!pallowed.includes(pext)) { per.textContent='Please choose a .eml, .msg, or image file.'; return; }")
if old_js in content:
    content = content.replace(old_js, new_js, 1)
    print("OK: JS validation updated")
else:
    print("MISS: JS validation not found")

# 5. Update the subtitle inside phishing tab
old_sub = 'STATIC ANALYSIS ONLY &mdash; NOTHING IS EXECUTED &mdash; .EML'
new_sub = 'STATIC ANALYSIS &mdash; .EML &middot; .MSG &middot; SCREENSHOTS'
if old_sub in content:
    content = content.replace(old_sub, new_sub, 1)
    print("OK: subtitle updated")

# 6. Also add analysis_method display to renderPhishingResult if screenshot
old_fname_display = "h += '<div class=\"kv\"><b>File:</b> ' + escapeHtml(r.filename) + '</div>';"
new_fname_display = ("h += '<div class=\"kv\"><b>File:</b> ' + escapeHtml(r.filename) + '</div>';\n"
                     "    if (r.analysis_method) h += '<div class=\"ioc-muted\" style=\"margin-bottom:8px;\">' + escapeHtml(r.analysis_method) + ' \u2014 authentication fields unavailable from screenshots</div>';")
if old_fname_display in content:
    content = content.replace(old_fname_display, new_fname_display, 1)
    print("OK: analysis method display added")
else:
    print("MISS: filename display line not found")

with open('src/dashboard/app.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)
print("Route + UI updates done.")
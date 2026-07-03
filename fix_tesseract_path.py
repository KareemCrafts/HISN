with open('src/parsers/email_parser.py', 'r', encoding='utf-8') as f:
    content = f.read()

old = "from PIL import Image\n        import pytesseract\n        img = Image.open(filepath)"
new = (
    "from PIL import Image\n"
    "        import pytesseract\n"
    "        import os\n"
    "        # Auto-detect Tesseract on Windows\n"
    "        for _p in [\n"
    "            r'C:\\Program Files\\Tesseract-OCR\\tesseract.exe',\n"
    "            r'C:\\Program Files (x86)\\Tesseract-OCR\\tesseract.exe',\n"
    "            r'C:\\Users\\' + os.environ.get('USERNAME','') + r'\\AppData\\Local\\Programs\\Tesseract-OCR\\tesseract.exe',\n"
    "        ]:\n"
    "            if os.path.exists(_p):\n"
    "                pytesseract.pytesseract.tesseract_cmd = _p\n"
    "                break\n"
    "        img = Image.open(filepath)"
)
if old in content:
    content = content.replace(old, new, 1)
    with open('src/parsers/email_parser.py', 'w', encoding='utf-8', newline='\n') as f:
        f.write(content)
    print("Tesseract path fix applied.")
else:
    print("Pattern not found — Tesseract section may already be patched or different.")
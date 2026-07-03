import re

with open('src/dashboard/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

fixes = []

# ── 1. LEDGER: CSS override (force containment) ───────────────────────
LEDGER_CSS = """
  /* LEDGER OVERFLOW FIX: hard containment regardless of signal count */
  .case-ledger{ overflow:hidden; }
  .ledger-num{
    font-family:'JetBrains Mono',monospace !important;
    font-size:13px !important;
    font-weight:700; color:#EAFFF2; line-height:1.15;
    text-align:center; width:100%;
    word-break:break-all; overflow:hidden;
    padding:0 2px; letter-spacing:-.01em;
  }
  .ledger-num small{
    display:block; font-family:'JetBrains Mono',monospace;
    font-size:7px; letter-spacing:.28em; color:var(--meta);
    margin-top:5px; text-transform:uppercase; white-space:nowrap;
  }
"""

if 'LEDGER OVERFLOW FIX' not in content:
    content = content.replace('</style>', LEDGER_CSS + '\n</style>', 1)
    fixes.append("Ledger overflow CSS")

# ── 2. LEDGER: JS produces max 3-char compact number ─────────────────
old_compact = ("      var compact = num >= 100000\n"
               "        ? Math.round(num/1000) + 'k'\n"
               "        : (num/1000).toFixed(1) + 'k';")
new_compact  = ("      var compact = num >= 1000000\n"
                "        ? Math.floor(num/1000000) + 'M'\n"
                "        : Math.floor(num/1000) + 'K';")
if old_compact in content:
    content = content.replace(old_compact, new_compact, 1)
    fixes.append("Ledger number: 10685 → 10K (3 chars, fits rail)")
else:
    # Try to patch whatever compact formatter exists
    for old_c in [
        "(num/1000).toFixed(1) + 'k'",
        "(num/1000).toFixed(1) + 'K'",
    ]:
        if old_c in content:
            content = content.replace(old_c, "Math.floor(num/1000) + 'K'", 1)
            fixes.append("Ledger number compact (alt patch)")
            break

# ── 3. TAGLINE ────────────────────────────────────────────────────────
for old_t in [
    "YOUR ENTIRE INVESTIGATION, ALL IN ONE PLACE.",
    "Your entire investigation, all in one place.",
]:
    if old_t in content:
        content = content.replace(old_t, "Everything your investigation needs. One workspace.", 1)
        fixes.append("Tagline updated")
        break

# ── 4. MOBILE NOTICE + FOOTER CSS ─────────────────────────────────────
MOBILE_FOOTER_CSS = """
  /* MOBILE NOTICE */
  .mobile-notice{
    display:none;
    position:fixed; top:0; left:0; right:0; z-index:200;
    background:rgba(5,8,12,.96); border-bottom:1px solid var(--rule);
    padding:10px 16px;
    font-family:'JetBrains Mono',monospace; font-size:10px;
    letter-spacing:.12em; color:var(--meta);
    text-align:center; backdrop-filter:blur(8px);
  }
  .mobile-notice span{ color:var(--acid); }
  @media(max-width:768px){ .mobile-notice{ display:block; } }

  /* FOOTER */
  .hisn-footer{
    margin-top:60px; padding:18px 0; text-align:center;
    border-top:1px solid rgba(0,255,170,.07);
    font-family:'JetBrains Mono',monospace;
    font-size:9px; letter-spacing:.2em; text-transform:uppercase;
    color:rgba(91,122,117,.5);
    position:relative; z-index:5;
  }
  .hisn-footer a{
    color:rgba(124,255,178,.3); text-decoration:none;
    transition:color .2s;
  }
  .hisn-footer a:hover{ color:rgba(124,255,178,.7); }
"""

if 'mobile-notice' not in content:
    content = content.replace('</style>', MOBILE_FOOTER_CSS + '\n</style>', 1)
    fixes.append("Mobile notice + footer CSS")

# ── 5. INJECT MOBILE NOTICE HTML ─────────────────────────────────────
MOBILE_HTML = ('<div class="mobile-notice">'
               '<span>&#9651; Desktop recommended</span>'
               ' &mdash; HISN is optimised for 1280px+ screens. '
               'Some investigation panels may be limited on mobile.</div>\n\n')

if 'mobile-notice' not in content or 'Desktop recommended' not in content:
    content = content.replace('<canvas id="rain"></canvas>', MOBILE_HTML + '<canvas id="rain"></canvas>', 1)
    fixes.append("Mobile notice HTML injected")

# ── 6. INJECT FOOTER HTML ────────────────────────────────────────────
FOOTER_HTML = ('\n\n<footer class="hisn-footer">\n'
               '  &copy; 2026 HISN &middot; '
               'Built by <a href="https://github.com/KareemCrafts" target="_blank">Kareem Alshaer</a>'
               ' &middot; All rights reserved\n'
               '</footer>')

if 'hisn-footer' not in content:
    content = content.replace('</body>', FOOTER_HTML + '\n</body>', 1)
    fixes.append("Footer injected")

with open('src/dashboard/app.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)

print("Fixes:")
for f2 in fixes: print(f"  OK: {f2}")
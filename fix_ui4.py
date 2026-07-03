import re

with open('src/dashboard/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

fixes = []

# ── 1. FIX LEDGER NUMBER OVERFLOW ─────────────────────────────────────
# Add CSS fix
LEDGER_CSS = """
  /* Ledger number: scales down for large counts, never overflows the rail */
  .ledger-num{
    font-family:'JetBrains Mono', monospace;
    font-size: clamp(10px, 2.8vw, 22px);
    color:#EAFFF2; line-height:1.1;
    text-align:center;
    max-width:52px;
    word-break:break-all;
    overflow-wrap:break-word;
    padding: 0 4px;
  }
  .ledger-num small{
    display:block; font-family:'JetBrains Mono', monospace;
    font-size:8px; letter-spacing:.32em; color:var(--meta);
    margin-top:6px; text-transform:uppercase;
    white-space:nowrap;
  }
"""

if '.ledger-num{' not in content and 'ledger-num clamp' not in content:
    content = content.replace('</style>', LEDGER_CSS + '\n</style>', 1)
    fixes.append("Ledger number: responsive font + overflow protection")

# Add JS formatter that abbreviates large numbers
LEDGER_JS = """
  // Compact ledger numbers — 10685 → 10.7k, keeps the box clean
  (function formatLedgerNumbers(){
    document.querySelectorAll('.ledger-num').forEach(function(el){
      var textNode = Array.from(el.childNodes).find(function(n){ return n.nodeType === 3; });
      if (!textNode) return;
      var raw = textNode.textContent.trim();
      var num = parseInt(raw.replace(/[^0-9]/g,''), 10);
      if (isNaN(num) || num < 10000) return;
      var compact = num >= 100000
        ? Math.round(num/1000) + 'k'
        : (num/1000).toFixed(1) + 'k';
      textNode.textContent = compact;
    });
  })();

"""

js_anchor = "  document.querySelectorAll('.cell.hit').forEach"
if js_anchor in content and 'formatLedgerNumbers' not in content:
    content = content.replace(js_anchor, LEDGER_JS + '\n  ' + "document.querySelectorAll('.cell.hit').forEach", 1)
    fixes.append("Ledger number: JS compact formatter (10685 → 10.7k)")

# ── 2. UPLOAD HEADING TYPOGRAPHY ──────────────────────────────────────
# Override only the h3 in .dropzone — no layout change
HEADING_CSS = """
  /* Upload heading: cleaner, enterprise-grade — same feel, more legible */
  .dropzone h3{
    font-family: 'Space Grotesk', sans-serif;
    font-weight: 700;
    font-size: 16px;
    letter-spacing: 0.14em;
    color: #EAFFF2;
    margin: 0 0 8px;
    text-transform: uppercase;
    text-rendering: optimizeLegibility;
    -webkit-font-smoothing: antialiased;
  }
  .dropzone-eyebrow{
    display: block;
    font-family: 'JetBrains Mono', monospace;
    font-size: 9px;
    letter-spacing: 0.42em;
    color: var(--meta);
    text-transform: uppercase;
    margin-bottom: 10px;
    opacity: .75;
    position: relative;
    z-index: 1;
  }
"""

if 'dropzone-eyebrow' not in content:
    content = content.replace('</style>', HEADING_CSS + '\n</style>', 1)
    fixes.append("Upload heading: Space Grotesk 700 (cleaner, enterprise-grade)")

# Inject eyebrow span before h3 in template
old_h3 = '<h3>DROP .EVTX TELEMETRY</h3>'
new_h3 = ('<span class="dropzone-eyebrow">WINDOWS EVENT LOG &middot; EVTX</span>\n'
          '    <h3>Drop File to Analyze</h3>')
if old_h3 in content:
    content = content.replace(old_h3, new_h3, 1)
    fixes.append("Upload heading: added eyebrow label, cleaner heading text")
else:
    # Try just changing the font via CSS without touching HTML
    fixes.append("Upload heading: CSS applied (h3 text unchanged)")

with open('src/dashboard/app.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)

print("Fixes applied:")
for f2 in fixes:
    print(f"  OK: {f2}")
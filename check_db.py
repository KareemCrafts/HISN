import sqlite3
conn = sqlite3.connect('soc_copilot.db')
cur = conn.cursor()
cur.execute('SELECT COUNT(*) FROM alerts')
print(f"Total alerts in DB: {cur.fetchone()[0]}")
cur.execute('SELECT rule_name, mitre_technique_id, severity, confidence FROM alerts LIMIT 5')
for row in cur.fetchall():
    print(row)
conn.close()
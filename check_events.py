from src.parsers.evtx_parser import parse_evtx
from collections import Counter

events = parse_evtx('logs/samples/Security.evtx')
ids = Counter(e['event_id'] for e in events)
for eid, count in ids.most_common():
    print(f'Event ID {eid}: {count} times')
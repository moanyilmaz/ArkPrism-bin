import json, sys

old_path = sys.argv[1]
new_path = sys.argv[2]

old = json.load(open(old_path, encoding='utf-8'))
new = json.load(open(new_path, encoding='utf-8'))

def mk(u):
    return u['namespace'] + '|' + u['method'] + '|' + u['code']

obk = {}
nbk = {}
for u in old['privacyApiUsages']:
    obk[mk(u)] = u
for u in new['privacyApiUsages']:
    nbk[mk(u)] = u

oo = set(obk.keys()) - set(nbk.keys())
on = set(nbk.keys()) - set(obk.keys())

print('=== ONLY IN OLD ===')
for k in sorted(oo):
    u = obk[k]
    print(f'{k} dm={u["declaringMethod"]} chains={len(u.get("callChains", []))}')

print()
print('=== ONLY IN NEW ===')
for k in sorted(on):
    u = nbk[k]
    print(f'{k} dm={u["declaringMethod"]} chains={len(u.get("callChains", []))}')

# Also compare chain counts for APIs that exist in both
print()
print('=== CHAIN COUNT DIFFERENCES (common APIs) ===')
common = set(obk.keys()) & set(nbk.keys())
for k in sorted(common):
    oc = len(obk[k].get('callChains', []))
    nc = len(nbk[k].get('callChains', []))
    if oc != nc:
        print(f'{k} old={oc} new={nc}')

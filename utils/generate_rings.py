import json
import sys

N = int(sys.argv[1])

keyring = dict()

for i in range(0, N):
	with open(f"all_keys/{i}.key") as f:
		data = json.load(f)
	keyring[str(i)] = data["pubkey"]


print(keyring)
with open(f"pubkeyring_{N}.keys", 'w') as fp:
    json.dump(keyring, fp, ensure_ascii=False)
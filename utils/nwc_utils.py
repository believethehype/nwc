import json
import requests
from nostr_sdk import Keys, PublicKey, Client, nip04_encrypt, EventBuilder, Tag


def nwc_zap(connectionstr, bolt11, keys):
    target_pubkey, relay, secret = parse_connection_str(connectionstr)
    SecretSK = Keys.from_sk_str(secret)

    content = {
        "method": "pay_invoice",
        "params": {
            "invoice": bolt11
        }
    }

    client = Client(keys)
    client.add_relay(relay)
    client.connect()

    client_public_key = PublicKey.from_hex(target_pubkey)
    encrypted_content = nip04_encrypt(SecretSK.secret_key(), client_public_key, json.dumps(content))

    pTag = Tag.parse(["p", client_public_key.to_hex()])
    event = EventBuilder(23194, encrypted_content,
                         [pTag]).to_event(keys)

    event_id = client.send_event(event)
    print(event_id.to_hex())


def parse_connection_str(connectionstring):
    split = connectionstring.split("?")
    targetpubkey = split[0].split(":")[1]
    split2 = split[1].split("&")
    relay = split2[0].split("=")[1]
    relay = relay.replace("%3A%2F%2F", "://")
    secret = split2[1].split("=")[1]
    return targetpubkey, relay, secret


def make_nwc_account(pubkey, nwcdomain, admin_key, lnbits_host):
    data = {
        'name': pubkey,  # Could be something else, a unique connection identifier
        'host': lnbits_host,
        'key': admin_key,
        'pubkey': pubkey,
    }

    try:
        url = nwcdomain
        header = {"content-type": "application/json"}
        res = requests.post(url, headers=header, json=data)
        obj = json.loads(res.text)
        if obj.get('params'):
            return obj['params']['connectionURI']
        else:
            return "Error: " + obj['error']['message']

    except Exception as e:
        print(e)
        return ""

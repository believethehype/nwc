import json
import urllib.parse

import lnurl
import requests
from nostr_sdk import PublicKey, Tag, EventBuilder


def pay_bolt11_ln_bits(bolt11: str, lnbits_admin_key: str, lnbits_host:str):
    url = lnbits_host + "/api/v1/payments"
    data = {'out': True, 'bolt11': bolt11}
    headers = {'X-API-Key': lnbits_admin_key, 'Content-Type': 'application/json', 'charset': 'UTF-8'}
    try:
        res = requests.post(url, json=data, headers=headers)
        obj = json.loads(res.text)
        if obj.get("payment_hash"):
            return obj["payment_hash"]
        else:
            print(res.text)
            return "Error"
    except Exception as e:
        print("LNBITS: " + str(e))
        return None, None

def zaprequest(lud16: str, amount: int, content, zapped_event, zapped_user: PublicKey, keys, relay_list, zaptype="public"):
    if lud16.startswith("LNURL") or lud16.startswith("lnurl"):
        url = lnurl.decode(lud16)
    elif '@' in lud16:  # LNaddress
        url = 'https://' + str(lud16).split('@')[1] + '/.well-known/lnurlp/' + str(lud16).split('@')[0]
    else:  # No lud16 set or format invalid
        return None
    try:
        response = requests.get(url)
        ob = json.loads(response.content)
        callback = ob["callback"]
        encoded_lnurl = lnurl.encode(url)
        amount_tag = Tag.parse(['amount', str(amount * 1000)])
        relays_tag = Tag.parse(['relays', str(relay_list)])
        lnurl_tag = Tag.parse(['lnurl', encoded_lnurl])
        if zapped_event is not None:
            p_tag = Tag.parse(['p', zapped_event.pubkey().to_hex()])
            e_tag = Tag.parse(['e', zapped_event.id().to_hex()])
            tags = [amount_tag, relays_tag, p_tag, e_tag, lnurl_tag]
        else:
            p_tag = Tag.parse(['p', zapped_user.to_hex()])
            tags = [amount_tag, relays_tag, p_tag, lnurl_tag]

        zap_request = EventBuilder(9734, content,
                                   tags).to_event(keys).as_json()

        response = requests.get(callback + "?amount=" + str(int(amount) * 1000) + "&nostr=" + urllib.parse.quote_plus(
            zap_request) + "&lnurl=" + encoded_lnurl)
        ob = json.loads(response.content)
        return ob["pr"]

    except Exception as e:
        print(e)
        return None

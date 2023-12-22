import json
import os
import threading
import time
from pathlib import Path
import dotenv
from nostr_sdk import Keys, Client, Timestamp, Filter, nip04_decrypt, HandleNotification, Tag, EventBuilder, \
    nip04_encrypt

from utils.db_utils import create_sql_table, add_to_sql_table, get_from_sql_table
from utils.zap_utils import pay_bolt11_ln_bits

from flask import request, Flask, jsonify

app = Flask(__name__)


@app.route('/api/new', methods=['GET', 'POST'])
def api_new_user():
    if request.method == 'POST':
        data = request.json
        print(jsonify(data))
        if os.getenv("NWC_PK") is not None:
            pk_str = os.getenv("NWC_PK")
        else:
            pk_str = Keys.generate().secret_key().to_hex()
            add_key_to_env_file("NWC_PK", pk_str)

        keys = Keys.from_sk_str(pk_str)

        id = data["name"]  # Could be something else, use npub for connection id for now
        npub = data['pubkey']
        secret = Keys.generate().secret_key().to_hex()
        lnbitskey = data['key']
        lnbitsdomain = data['host']

        user = get_from_sql_table("db/nwc", npub)
        if user is None:
            add_to_sql_table("db/nwc", id, npub, secret, lnbitskey, lnbitsdomain, time.time())

            content = {
                "result_type": "create_account",
                "params": {
                    "connectionURI": "nostr+walletconnect:" + keys.public_key().to_hex() + "?relay=" + os.getenv("RELAY").replace("wss://", "wss%3A%2F%2F") + "&secret=" + secret
                }
            }
            return jsonify(content)
        else:
            content = {
                "result_type": "create_account",
                "error": {
                    "code": "RESTRICTED",
                    "message": "User already exists"
                }
            }
            return jsonify(content)

    else:
        return "Send data to create a new user"

def flask():
    app.run(debug=True, use_reloader=False, port=5001, host='0.0.0.0')

def nwc():
    if os.getenv("NWC_PK") is not None:
        pk_str = os.getenv("NWC_PK")
    else:
        pk_str = Keys.generate().secret_key().to_hex()
        add_key_to_env_file("NWC_PK", pk_str)

    keys = Keys.from_sk_str(pk_str)
    pk = keys.public_key()
    print(f"NWC Client public key: {pk.to_bech32()}, Hex: {pk.to_hex()} ")
    client = Client(keys)
    client.add_relay(os.getenv("RELAY"))
    client.connect()

    create_sql_table("db/nwc")

    nwc_filter = (Filter().pubkey(pk).kinds([13194, 23194]).since(Timestamp.now()))  # public events
    client.subscribe([nwc_filter])

    class NotificationHandler(HandleNotification):
        def handle(self, relay_url, event):
            print(f"Received new event from {relay_url}: {event.as_json()}")
            if event.kind() == 13194:
                handle_nwc_info(event)
            elif event.kind() == 23194:
                handle_nwc_request(event)

        def handle_msg(self, relay_url, msg):
            return

    client.handle_notifications(NotificationHandler())
    while True:
        time.sleep(1.0)


def handle_nwc_info(event):
    print("[Nostr Client]: " + event.as_json())
    print("[Nostr Client]: " + event.content())


def handle_nwc_request(event):
    keys = Keys.from_sk_str(os.getenv("NWC_PK"))
    sk = keys.secret_key()

    print("Sender Pubkey: " + event.pubkey().to_hex())

    user = get_from_sql_table("db/nwc", event.pubkey().to_hex())
    userkeys = Keys.from_sk_str(user.secret)

    decrypted = nip04_decrypt(sk, userkeys.public_key(), event.content())
    request = json.loads(decrypted)

    if request['method'] == "pay_invoice":
        bolt11 = request['params']['invoice']
        preimage = pay_bolt11_ln_bits(bolt11, user.lnbitskey, user.lnbitsdomain)
        print("Preimage: " + preimage)

        content = {
            "result_type": "pay_invoice",
            "result": {
                "preimage": preimage
            }
        }
        encrypt_keys = Keys.from_sk_str(user.secret).public_key()

        encrypted_content = nip04_encrypt(sk, encrypt_keys, json.dumps(content))
        pTag = Tag.parse(["p", event.pubkey().to_hex()])
        event = EventBuilder(23195, encrypted_content,
                             [pTag]).to_event(keys)

        client = Client(keys)
        client.add_relay(os.getenv("RELAY"))
        client.connect()
        time.sleep(1.0)
        event_id = client.send_event(event)
        print("Reply EventID: " + event_id.to_hex())
        client.disconnect()


def add_key_to_env_file(value, oskey):
    env_path = Path('.env')
    if env_path.is_file():
        dotenv.load_dotenv(env_path, verbose=True, override=True)
        dotenv.set_key(env_path, value, oskey)


if __name__ == '__main__':
    env_path = Path('.env')
    if not env_path.is_file():
        with open('.env', 'w') as f:
            print("Writing new .env file")
            f.write('')
    elif env_path.is_file():
        print(f'loading environment from {env_path.resolve()}')
        dotenv.load_dotenv(env_path, verbose=True, override=True)

    try:
        print(f'start first thread')
        t1 = threading.Thread(target=flask).start()
        print(f'start second thread')
        t2 = threading.Thread(target=nwc).start()
    except Exception as e:
        print("Unexpected error:" + str(e))

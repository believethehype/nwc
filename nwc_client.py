import os
import threading
import time
from pathlib import Path

import dotenv
from nostr_sdk import Keys, Client, Filter, Timestamp, PublicKey, HandleNotification, nip04_decrypt

from main import add_key_to_env_file
from utils.nwc_utils import nwc_zap, make_nwc_account, parse_connection_str
from utils.zap_utils import zaprequest


def nostr_client():
    if os.getenv("CLIENT_PK") is not None:
        pk_str = os.getenv("CLIENT_PK")
    else:
        pk_str = Keys.generate().secret_key().to_hex()
        add_key_to_env_file("CLIENT_PK", pk_str)

    keys = Keys.from_sk_str(pk_str)
    pk = keys.public_key()
    print(f"Nostr Client public key: {pk.to_bech32()}, Hex: {pk.to_hex()} ")
    client = Client(keys)
    client.add_relay(os.getenv("RELAY"))
    client.connect()

    nwc_filter = Filter().pubkey(pk).kinds([23195]).since(Timestamp.now())  # public events
    client.subscribe([nwc_filter])

    class NotificationHandler(HandleNotification):
        def handle(self, relay_url, event):
            print(f"Received new event from {relay_url}: {event.as_json()}")
            if event.kind() == 23195:
                target_pubkey, relay, secret = parse_connection_str(os.getenv("TEST_NWC_STRING"))
                sk = Keys.from_sk_str(secret).secret_key()
                decrypted = nip04_decrypt(sk, event.pubkey(), event.content())
                print(decrypted)

        def handle_msg(self, relay_url, msg):
            return

    client.handle_notifications(NotificationHandler())


    while True:
        time.sleep(1.0)


def test_nwc():
    keys = Keys.from_sk_str(os.getenv("CLIENT_PK"))
    lnbits_admin_key = os.getenv("LNBITS_ADMIN_KEY_TEST")
    lnbits_host = os.getenv("LNBITS_HOST")

    # PART 1 MAKE A NEW NWC Connection String
    if not os.getenv("TEST_NWC_STRING"):
        # Note this doesn't have to be the client, it should be a users key, but in order to test we use our own key
        connectionstring = make_nwc_account(keys.public_key().to_hex(), "http://localhost:5001/api/new",
                                            lnbits_admin_key,
                                            lnbits_host, )
        print("NWC connection string: " + connectionstring)

        # for now we store the single connection string in the .env, but this should be a database
        add_key_to_env_file("TEST_NWC_STRING", connectionstring)
    # PART 2 use the NWC String to zap
    # That's why we added ourself
    if os.getenv("TEST_NWC_STRING"):
        RELAY_LIST = ["wss://relay.damus.io", "wss://nostr-pub.wellorder.net", "wss://nos.lol", "wss://nostr.wine",
                      "wss://relay.nostfiles.dev", "wss://nostr.mom", "wss://nostr.oxtr.dev", "wss://relay.nostr.bg",
                      "wss://relay.f7z.io", "wss://pablof7z.nostr1.com", "wss://purplepag.es", "wss://nos.lol",
                      "wss://relay.snort.social", "wss://offchain.pub/",
                      "wss://nostr-pub.wellorder.net"]

        # we zap npub1nxa4tywfz9nqp7z9zp7nr7d4nchhclsf58lcqt5y782rmf2hefjquaa6q8's profile 21 sats and say 'GFM''
        # Therefore we first do a regular zaprequest to obtain a bolt11 from their lud16
        bolt11 = zaprequest("hype@bitcoinfixesthis.org", 21, "GFM", None,
                            PublicKey.from_bech32("npub1nxa4tywfz9nqp7z9zp7nr7d4nchhclsf58lcqt5y782rmf2hefjquaa6q8"),
                            keys, RELAY_LIST)

        # we then send a zap request via nwc using our nwc string, the bolt11 and our keys.
        nwc_zap(os.getenv("TEST_NWC_STRING"), bolt11, keys)


if __name__ == '__main__':
    env_path = Path('.env')
    if env_path.is_file():
        print(f'loading environment from {env_path.resolve()}')
        dotenv.load_dotenv(env_path, verbose=True, override=True)
    else:
        raise FileNotFoundError(f'.env file not found at {env_path} ')

    t1 = threading.Thread(target=nostr_client).start()
    t2 = threading.Thread(target=test_nwc).start()

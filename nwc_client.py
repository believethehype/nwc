
import os
import threading
import time
from pathlib import Path

import dotenv
from nostr_sdk import Keys, Client, Filter, Timestamp, PublicKey, HandleNotification

from main import add_key_to_env_file
from utils.nwc_utils import nwc_zap, make_nwc_account
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
    client.add_relay("wss://relay.getalby.com/v1")

    client.connect()

    nwc_filter = (Filter().pubkey(pk).kinds([23195]).since(Timestamp.now()))  # public events
    client.subscribe([nwc_filter])

    class NotificationHandler(HandleNotification):
        def handle(self, relay_url, event):
            print(f"Received new event from {relay_url}: {event.as_json()}")
            if event.kind() == 23195:
                print(event)

        def handle_msg(self, relay_url, msg):
            return

    client.handle_notifications(NotificationHandler())
    while True:
        time.sleep(1.0)


if __name__ == '__main__':
    env_path = Path('.env')
    if env_path.is_file():
        print(f'loading environment from {env_path.resolve()}')
        dotenv.load_dotenv(env_path, verbose=True, override=True)
    else:
        raise FileNotFoundError(f'.env file not found at {env_path} ')

    keys = Keys.from_sk_str(os.getenv("PRIVATE_KEY_TEST"))
    lnbits_admin_key = os.getenv("LNBITS_ADMIN_KEY_TEST")
    lnbits_host = os.getenv("LNBITS_HOST")

    # PART 1 MAKE A NEW NWC Connection String
    connectionstring = make_nwc_account(keys.public_key().to_hex(), "http://localhost:5001/api/new", lnbits_admin_key, lnbits_host, )
    print("NWCSTRING: " + connectionstring)


    # PART 2 use the NWC String to zap
    # Don't do this necesarily in one run, get the nwc string and add it here.
    #  TODO Store the connection string in a db, manually add here if you already have one
    connectionstring = "nostr+walletconnect:fa42efbb68b7f4455836c2f5df3f3baa83143ac9b3b93df7c3e57d96b5aca958?relay=wss%3A%2F%2Frelay.getalby.com/v1&secret=b94e8c11b9290fee0a924b83b706eaabf7f24e3bb147ef0dafb35a0a9b566699"
    if connectionstring != "":
        RELAY_LIST = ["wss://relay.damus.io", "wss://nostr-pub.wellorder.net", "wss://nos.lol", "wss://nostr.wine",
                      "wss://relay.nostfiles.dev", "wss://nostr.mom", "wss://nostr.oxtr.dev", "wss://relay.nostr.bg",
                      "wss://relay.f7z.io", "wss://pablof7z.nostr1.com", "wss://purplepag.es", "wss://nos.lol",
                      "wss://relay.snort.social", "wss://offchain.pub/",
                      "wss://nostr-pub.wellorder.net"]

        # we zap npub1nxa4tywfz9nqp7z9zp7nr7d4nchhclsf58lcqt5y782rmf2hefjquaa6q8's profile 21 sats and say Cool stuff
        # Therefore we first do a regular zaprequest to obtain a bolt11 from their lud16
        pubkey = PublicKey.from_bech32("npub1nxa4tywfz9nqp7z9zp7nr7d4nchhclsf58lcqt5y782rmf2hefjquaa6q8")
        bolt11 = zaprequest("hype@bitcoinfixesthis.org", 21, "Cool Stuff", None,
                            pubkey, keys, RELAY_LIST)

        # we then send a zap request via nwc using our nwc string, the bolt11 and our keys.
        nwc_zap(connectionstring, bolt11, keys)

        # Listen to responses
    t1 = threading.Thread(target=nostr_client()).start()

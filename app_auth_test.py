from datetime import datetime, timezone
import json
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

# sign - Client APP


with open("app_auth_test_priv.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(), password=None, backend=default_backend()
    )


auth_payload = {
    "app_name": "qlol",
    "datetime": datetime.now(tz=timezone.utc).isoformat(),
}

auth_message_bytes = json.dumps(auth_payload).encode("utf-8")

signature = private_key.sign(
    auth_message_bytes,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256(),
)

auth_payload["signature"] = base64.b64encode(signature).decode("utf-8")

auth_payload = json.dumps(auth_payload)
print(auth_payload)


# verify - VIP

with open("app_auth_test_pub.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(), backend=default_backend()
    )


request_payload = json.loads(auth_payload)

try:
    public_key.verify(
        base64.b64decode(request_payload.pop("signature").encode("utf-8")),
        json.dumps(request_payload).encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
except InvalidSignature:
    print("signatue in invalid")

print("{} is verified give it a JWT".format(request_payload['app_name']))

import base64
import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def _cf_safe_b64(data: bytes) -> str:
    return (
        base64.b64encode(data).decode("utf-8")
        .replace("+", "-").replace("=", "_").replace("/", "~")
    )

def sign_cloudfront_url(resource_url: str, key_pair_id: str, private_key_pem_path: str, expires_in_seconds: int = 3600) -> str:
    expires = int((datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in_seconds)).timestamp())
    policy = (
        '{'
        '"Statement":[{'
        f'"Resource":"{resource_url}",'
        '"Condition":{"DateLessThan":{"AWS:EpochTime":' + str(expires) + "}}"
        "}]"
        "}"
    )

    with open(private_key_pem_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    signature = private_key.sign(
        policy.encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA1(),
    )

    return (
        f"{resource_url}"
        f"?Policy={_cf_safe_b64(policy.encode('utf-8'))}"
        f"&Signature={_cf_safe_b64(signature)}"
        f"&Key-Pair-Id={key_pair_id}"
    )
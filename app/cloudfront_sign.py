import base64
import datetime
from functools import lru_cache
from typing import Optional

import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def _cf_safe_b64(data: bytes) -> str:
    return (
        base64.b64encode(data)
        .decode("utf-8")
        .replace("+", "-")
        .replace("=", "_")
        .replace("/", "~")
    )


def _get_secret_string(
    secret_name: str,
    region_name: str,
    version_stage: str = "AWSCURRENT",
) -> str:
    """
    Fetch a secret string from AWS Secrets Manager.
    The secret should be stored as SecretString (not binary).
    """
    client = boto3.client("secretsmanager", region_name=region_name)
    try:
        resp = client.get_secret_value(SecretId=secret_name, VersionStage=version_stage)
    except ClientError as e:
        raise RuntimeError(f"Failed to read secret '{secret_name}' from Secrets Manager") from e

    if "SecretString" in resp and resp["SecretString"]:
        return resp["SecretString"]

    # If you stored it as binary, you can handle it here:
    if "SecretBinary" in resp and resp["SecretBinary"]:
        return base64.b64decode(resp["SecretBinary"]).decode("utf-8")

    raise RuntimeError(f"Secret '{secret_name}' contained no SecretString/SecretBinary")


@lru_cache(maxsize=1)
def _load_cloudfront_private_key_from_secrets_manager(
    secret_name: str,
    region_name: str,
) -> serialization.PrivateFormat:
    """
    Load and cache the CloudFront private key (PEM) from Secrets Manager.
    Caching prevents a Secrets Manager call on every request.
    """
    pem_str = _get_secret_string(secret_name=secret_name, region_name=region_name)
    pem_bytes = pem_str.encode("utf-8")

    try:
        return serialization.load_pem_private_key(pem_bytes, password=None)
    except Exception as e:
        raise RuntimeError(
            f"Secret '{secret_name}' did not contain a valid PEM private key"
        ) from e


def sign_cloudfront_url(
    resource_url: str,
    key_pair_id: str,
    *,
    secret_name: str = "cloudfront_private_key",
    region_name: str = "eu-central-1",
    expires_in_seconds: int = 3600,
) -> str:
    """
    Create a CloudFront signed URL using a private key stored in AWS Secrets Manager.

    Store the *full PEM* (including -----BEGIN...----- lines) as the SecretString.
    """
    expires = int(
        (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=expires_in_seconds))
        .timestamp()
    )

    policy = (
        "{"
        '"Statement":[{'
        f'"Resource":"{resource_url}",'
        '"Condition":{"DateLessThan":{"AWS:EpochTime":' + str(expires) + "}}"
        "}]"
        "}"
    )

    private_key = _load_cloudfront_private_key_from_secrets_manager(
        secret_name=secret_name,
        region_name=region_name,
    )

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
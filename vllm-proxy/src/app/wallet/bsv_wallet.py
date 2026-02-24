"""BSV wallet initialization for the TEE inference proxy."""
import os
import hashlib
import logging

from bsv.keys import PrivateKey
from bsv.wallet import KeyDeriver
from sqlalchemy import create_engine

from bsv_wallet_toolbox import Wallet
from bsv_wallet_toolbox.services import Services, create_default_options
from bsv_wallet_toolbox.storage import StorageProvider

logger = logging.getLogger(__name__)

# Module-level singleton
_wallet: Wallet | None = None
_tee_private_key: PrivateKey | None = None
_tee_public_key_hex: str | None = None

# Protocol constants — MUST match TypeScript @bsv/mandala-tee/constants.ts
TEE_ATTESTATION_PROTOCOL = [2, "mandala tee attestation"]
TEE_ATTESTATION_BASKET = "mandala_tee_attestations"
INFERENCE_RECEIPT_PROTOCOL = [2, "mandala inference receipt"]
INFERENCE_RECEIPT_BASKET = "mandala_inference_receipts"
INFERENCE_SIGNING_PROTOCOL = [2, "mandala inference signing"]
TEE_ATTESTATION_MARKER = "mandala-tee-attestation-v1"
INFERENCE_BATCH_MARKER = "mandala-inference-batch-v1"


def init_wallet() -> tuple[Wallet, str]:
    """
    Initialize the BSV wallet with a fresh random key generated inside the CVM.
    Returns (wallet, tee_public_key_hex).
    Called once at startup.
    """
    global _wallet, _tee_private_key, _tee_public_key_hex

    chain = os.environ.get("BSV_CHAIN", "main")

    # Generate a fresh key INSIDE the CVM — private key never leaves
    _tee_private_key = PrivateKey()
    _tee_public_key_hex = _tee_private_key.public_key().hex()
    logger.info(f"Generated TEE BSV key: {_tee_public_key_hex}")

    # Create wallet with local SQLite storage inside the CVM
    key_deriver = KeyDeriver(root_private_key=_tee_private_key)
    options = create_default_options(chain)
    services = Services(options)

    # SQLite file inside the CVM — ephemeral, lost when CVM shuts down
    db_path = os.environ.get("BSV_WALLET_DB", "/tmp/tee_wallet.db")
    engine = create_engine(f"sqlite:///{db_path}")
    storage = StorageProvider(
        engine=engine,
        chain=chain,
        storage_identity_key=_tee_public_key_hex,
    )
    storage.make_available()
    storage.set_services(services)

    _wallet = Wallet(
        chain=chain,
        services=services,
        key_deriver=key_deriver,
        storage_provider=storage,
    )

    return _wallet, _tee_public_key_hex


def get_wallet() -> Wallet:
    """Get the initialized wallet. Raises if not initialized."""
    if _wallet is None:
        raise RuntimeError("BSV wallet not initialized. Call init_wallet() first.")
    return _wallet


def get_tee_public_key() -> str:
    """Get the TEE public key hex. Raises if not initialized."""
    if _tee_public_key_hex is None:
        raise RuntimeError("BSV wallet not initialized. Call init_wallet() first.")
    return _tee_public_key_hex


def get_report_data_for_attestation() -> bytes:
    """
    Build the 64-byte report_data for TDX attestation:
    First 32 bytes = SHA256(compressed_pubkey_bytes)
    Last 32 bytes = zeros

    This binds the BSV public key to the TDX quote.
    """
    if _tee_public_key_hex is None:
        raise RuntimeError("BSV wallet not initialized.")
    pubkey_bytes = bytes.fromhex(_tee_public_key_hex)
    pubkey_hash = hashlib.sha256(pubkey_bytes).digest()
    return pubkey_hash + b"\x00" * 32


def sign_data(data: bytes, key_id: str) -> bytes:
    """
    Sign arbitrary data using BRC-100 create_signature.
    Returns DER-encoded ECDSA signature bytes.
    """
    wallet = get_wallet()
    result = wallet.create_signature({
        "data": list(data),
        "protocolID": INFERENCE_SIGNING_PROTOCOL,
        "keyID": key_id,
        "counterparty": "anyone",
    })
    return bytes(result["signature"])

"""Publish TEE attestation as a PushDrop token on BSV and register with Mandala Node."""
import hashlib
import logging
import os
from datetime import datetime, timezone

import requests

from app.wallet.bsv_wallet import (
    get_wallet,
    get_tee_public_key,
    TEE_ATTESTATION_MARKER,
    TEE_ATTESTATION_PROTOCOL,
    TEE_ATTESTATION_BASKET,
)
from app.wallet.pushdrop_utils import build_pushdrop_locking_script

logger = logging.getLogger(__name__)

_attestation_txid: str | None = None


def get_attestation_id() -> str:
    """Get the current attestation txid. Returns 'pending' if not yet published."""
    return _attestation_txid or "pending"


async def publish_attestation(
    intel_quote_hex: str,
    mr_enclave: str,
    mr_signer: str,
    gpu_evidence_hash: str | None,
    tee_technology: str = "tdx",
) -> str:
    """
    Publish a PushDrop attestation token on BSV.
    Returns the attestation txid.
    """
    global _attestation_txid

    wallet = get_wallet()
    tee_pubkey = get_tee_public_key()
    node_identity_key = os.environ.get("NODE_IDENTITY_KEY", "unknown")
    tdx_quote_hash = hashlib.sha256(bytes.fromhex(intel_quote_hex)).hexdigest()
    timestamp = datetime.now(timezone.utc).isoformat()

    # Build PushDrop fields (9 fields, matching TypeScript ATTESTATION_FIELDS)
    fields = [
        TEE_ATTESTATION_MARKER,
        node_identity_key,
        tee_pubkey,
        tdx_quote_hash,
        mr_enclave,
        mr_signer,
        gpu_evidence_hash or "none",
        tee_technology,
        timestamp,
    ]

    locking_script_hex = build_pushdrop_locking_script(
        wallet=wallet,
        fields=[f.encode("utf-8") if isinstance(f, str) else f for f in fields],
        protocol_id=TEE_ATTESTATION_PROTOCOL,
        key_id=get_attestation_id(),
        counterparty="anyone",
    )

    # Publish via create_action (1 sat — spendable UTXO, not prunable)
    result = wallet.create_action({
        "outputs": [{
            "lockingScript": locking_script_hex,
            "satoshis": 1,
            "outputDescription": "TEE attestation token",
            "tags": [TEE_ATTESTATION_MARKER],
            "basket": TEE_ATTESTATION_BASKET,
        }],
        "description": "Publish TEE attestation to BSV overlay",
        "options": {"acceptDelayedBroadcast": True},
    })

    _attestation_txid = result.get("txid", "unknown")
    logger.info(f"Published TEE attestation: txid={_attestation_txid}")

    # Register with Mandala Node
    callback_url = os.environ.get("MANDALA_NODE_CALLBACK_URL")
    if callback_url:
        try:
            resp = requests.post(
                f"{callback_url.rstrip('/')}/attestation/register",
                json={
                    "attestationTxid": _attestation_txid,
                    "nodeIdentityKey": node_identity_key,
                    "teePublicKey": tee_pubkey,
                    "tdxQuoteHash": tdx_quote_hash,
                    "mrEnclave": mr_enclave,
                    "mrSigner": mr_signer,
                    "gpuEvidenceHash": gpu_evidence_hash,
                    "teeTechnology": tee_technology,
                    "attestedAt": timestamp,
                },
                timeout=10,
            )
            logger.info(f"Registered attestation with Mandala Node: {resp.status_code}")
        except Exception as e:
            logger.error(f"Failed to register attestation with Mandala Node: {e}")

    return _attestation_txid

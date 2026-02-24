"""Merkle-batched inference receipt accumulator."""
import hashlib
import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone

import requests

from app.wallet.bsv_wallet import (
    get_wallet,
    get_tee_public_key,
    sign_data,
    INFERENCE_BATCH_MARKER,
    INFERENCE_RECEIPT_PROTOCOL,
    INFERENCE_RECEIPT_BASKET,
)
from app.wallet.pushdrop_utils import build_pushdrop_locking_script
from app.attestation.anchor import get_attestation_id

logger = logging.getLogger(__name__)

BATCH_SIZE = int(os.environ.get("RECEIPT_BATCH_SIZE", "100"))
BATCH_INTERVAL_SECONDS = int(os.environ.get("RECEIPT_BATCH_INTERVAL", "300"))

_receipts: list[bytes] = []
_lock = threading.Lock()
_local_db: sqlite3.Connection | None = None


def _init_local_db():
    """Initialize local SQLite for receipt storage inside CVM."""
    global _local_db
    db_path = os.environ.get("RECEIPT_DB_PATH", "/tmp/receipts.db")
    _local_db = sqlite3.connect(db_path, check_same_thread=False)
    _local_db.execute("""
        CREATE TABLE IF NOT EXISTS receipts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            receipt_hash TEXT NOT NULL,
            batch_txid TEXT,
            merkle_index INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    _local_db.execute("""
        CREATE TABLE IF NOT EXISTS batches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_txid TEXT NOT NULL,
            merkle_root TEXT NOT NULL,
            receipt_count INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    _local_db.commit()


def add_receipt(request_hash: str, response_hash: str, chat_id: str):
    """Add an inference receipt to the accumulator."""
    receipt_data = f"{chat_id}:{request_hash}:{response_hash}".encode()
    receipt_hash = hashlib.sha256(receipt_data).digest()

    with _lock:
        _receipts.append(receipt_hash)

        if _local_db:
            _local_db.execute(
                "INSERT INTO receipts (receipt_hash) VALUES (?)",
                (receipt_hash.hex(),),
            )
            _local_db.commit()

        if len(_receipts) >= BATCH_SIZE:
            _flush_batch()


def _build_merkle_root(hashes: list[bytes]) -> bytes:
    """Build a Merkle root from a list of leaf hashes."""
    if not hashes:
        return b"\x00" * 32
    layer = list(hashes)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        next_layer = []
        for i in range(0, len(layer), 2):
            combined = layer[i] + layer[i + 1]
            next_layer.append(hashlib.sha256(combined).digest())
        layer = next_layer
    return layer[0]


def _flush_batch():
    """Publish accumulated receipts as a Merkle-rooted batch on BSV."""
    global _receipts
    if not _receipts:
        return

    batch_hashes = _receipts[:]
    _receipts = []

    merkle_root = _build_merkle_root(batch_hashes)
    receipt_count = len(batch_hashes)
    tee_pubkey = get_tee_public_key()
    node_identity_key = os.environ.get("NODE_IDENTITY_KEY", "unknown")
    attestation_id = get_attestation_id()
    timestamp = datetime.now(timezone.utc).isoformat()

    # Sign fields 0-5
    sig_data = f"{INFERENCE_BATCH_MARKER}:{merkle_root.hex()}:{receipt_count}:{node_identity_key}:{tee_pubkey}:{attestation_id}"
    sig_bytes = sign_data(sig_data.encode(), key_id=attestation_id)

    fields = [
        INFERENCE_BATCH_MARKER,
        merkle_root.hex(),
        str(receipt_count),
        node_identity_key,
        tee_pubkey,
        attestation_id,
        sig_bytes.hex(),
        timestamp,
    ]

    try:
        wallet = get_wallet()
        field_bytes = [f.encode("utf-8") if isinstance(f, str) else f for f in fields]
        locking_script_hex = build_pushdrop_locking_script(
            wallet=wallet,
            fields=field_bytes,
            protocol_id=INFERENCE_RECEIPT_PROTOCOL,
            key_id=attestation_id,
            counterparty="anyone",
        )

        result = wallet.create_action({
            "outputs": [{
                "lockingScript": locking_script_hex,
                "satoshis": 1,
                "outputDescription": "Inference receipt batch",
                "tags": [INFERENCE_BATCH_MARKER],
                "basket": INFERENCE_RECEIPT_BASKET,
            }],
            "description": f"Inference receipt batch ({receipt_count} receipts)",
            "options": {"acceptDelayedBroadcast": True},
        })

        batch_txid = result.get("txid", "unknown")
        logger.info(f"Published receipt batch: txid={batch_txid}, receipts={receipt_count}")

        if _local_db:
            _local_db.execute(
                "INSERT INTO batches (batch_txid, merkle_root, receipt_count) VALUES (?, ?, ?)",
                (batch_txid, merkle_root.hex(), receipt_count),
            )
            cursor = _local_db.execute(
                "SELECT id FROM receipts WHERE batch_txid IS NULL ORDER BY id LIMIT ?",
                (receipt_count,),
            )
            for idx, (row_id,) in enumerate(cursor.fetchall()):
                _local_db.execute(
                    "UPDATE receipts SET batch_txid = ?, merkle_index = ? WHERE id = ?",
                    (batch_txid, idx, row_id),
                )
            _local_db.commit()

        # Register with Mandala Node
        callback_url = os.environ.get("MANDALA_NODE_CALLBACK_URL")
        if callback_url:
            try:
                requests.post(
                    f"{callback_url.rstrip('/')}/receipts/register",
                    json={
                        "batchTxid": batch_txid,
                        "merkleRoot": merkle_root.hex(),
                        "receiptCount": receipt_count,
                        "nodeIdentityKey": node_identity_key,
                        "attestationTxid": attestation_id,
                    },
                    timeout=10,
                )
            except Exception as e:
                logger.error(f"Failed to register batch with Mandala Node: {e}")

    except Exception as e:
        logger.error(f"Failed to publish receipt batch: {e}")
        with _lock:
            _receipts = batch_hashes + _receipts


def start_batch_timer():
    """Start background thread that flushes receipts every BATCH_INTERVAL_SECONDS."""
    _init_local_db()

    def _timer_loop():
        while True:
            time.sleep(BATCH_INTERVAL_SECONDS)
            with _lock:
                if _receipts:
                    _flush_batch()

    t = threading.Thread(target=_timer_loop, daemon=True)
    t.start()
    logger.info(f"Receipt batch timer started (interval={BATCH_INTERVAL_SECONDS}s, batch_size={BATCH_SIZE})")

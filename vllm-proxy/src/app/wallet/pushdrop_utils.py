"""PushDrop locking script construction matching @bsv/sdk PushDrop.lock() format."""
import struct


OP_CHECKSIG = 0xAC
OP_2DROP = 0x6D
OP_DROP = 0x75
OP_PUSHDATA1 = 0x4C
OP_PUSHDATA2 = 0x4D
OP_PUSHDATA4 = 0x4E


def _minimal_push(data: bytes) -> bytes:
    """Encode data as a Bitcoin script minimal push (BIP-62 compliant)."""
    n = len(data)
    if n == 0 or (n == 1 and data[0] == 0):
        return bytes([0x00])  # OP_0
    if n == 1 and 1 <= data[0] <= 16:
        return bytes([0x50 + data[0]])  # OP_1 through OP_16
    if n == 1 and data[0] == 0x81:
        return bytes([0x4F])  # OP_1NEGATE
    if n <= 75:
        return bytes([n]) + data
    if n <= 255:
        return bytes([OP_PUSHDATA1, n]) + data
    if n <= 65535:
        return bytes([OP_PUSHDATA2]) + struct.pack("<H", n) + data
    return bytes([OP_PUSHDATA4]) + struct.pack("<I", n) + data


def build_pushdrop_locking_script(
    wallet,
    fields: list[bytes],
    protocol_id: list,
    key_id: str,
    counterparty: str = "anyone",
) -> str:
    """
    Build a PushDrop locking script hex string.
    Matches TypeScript @bsv/sdk PushDrop.lock(fields, protocolID, keyID, counterparty, true).

    Args:
        wallet: BSV Wallet instance (py-wallet-toolbox)
        fields: List of field byte arrays to embed
        protocol_id: [security_level, protocol_name]
        key_id: Key identifier string
        counterparty: "anyone" | "self" | hex pubkey

    Returns:
        Hex-encoded locking script string
    """
    # 1. Get the derived public key for the locking condition
    derived_pub_result = wallet.get_public_key({
        "protocolID": protocol_id,
        "keyID": key_id,
        "counterparty": counterparty,
        "forSelf": False,
    })
    derived_pubkey_hex = derived_pub_result["publicKey"]
    derived_pubkey_bytes = bytes.fromhex(derived_pubkey_hex)

    # 2. Sign the concatenation of all field bytes (data authenticity signature)
    all_field_bytes = b"".join(fields)
    sig_result = wallet.create_signature({
        "data": list(all_field_bytes),
        "protocolID": protocol_id,
        "keyID": key_id,
        "counterparty": counterparty,
    })
    data_sig_bytes = bytes(sig_result["signature"])

    # 3. Build the script
    script = bytearray()

    # Lock prefix: PUSH(33) <pubkey> OP_CHECKSIG
    script.append(0x21)  # push 33 bytes
    script.extend(derived_pubkey_bytes)
    script.append(OP_CHECKSIG)

    # Push each field
    for field in fields:
        script.extend(_minimal_push(field))

    # Push the data signature
    script.extend(_minimal_push(data_sig_bytes))

    # Drop sequence: total items = len(fields) + 1 (for data sig)
    total_items = len(fields) + 1
    for _ in range(total_items // 2):
        script.append(OP_2DROP)
    if total_items % 2 == 1:
        script.append(OP_DROP)

    return script.hex()

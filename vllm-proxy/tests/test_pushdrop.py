"""Cross-language PushDrop compatibility tests.

Tests the Python PushDrop implementation (pushdrop_utils.py) with known
test vectors that are shared with the TypeScript companion test
(packages/mandala-tee/src/__tests__/pushdrop-compat.test.ts).

Both tests must produce the exact same locking script hex.
"""

import struct
import unittest
from unittest.mock import MagicMock

from app.wallet.pushdrop_utils import (
    OP_2DROP,
    OP_CHECKSIG,
    OP_DROP,
    OP_PUSHDATA1,
    OP_PUSHDATA2,
    _minimal_push,
    build_pushdrop_locking_script,
)

# ---------------------------------------------------------------------------
# Shared test vectors (MUST match the TypeScript test exactly)
# ---------------------------------------------------------------------------
DERIVED_PUBKEY_HEX = "02" + "aa" * 32  # 33-byte compressed pubkey
FIELDS = [b"field-zero", b"field-one", b"field-two"]
DATA_SIG = bytes([0xBB] * 71)  # fake 71-byte DER signature


def _build_expected_hex() -> str:
    """Build the expected locking script hex from first principles."""
    script = bytearray()

    # Lock prefix: PUSH(33) <pubkey> OP_CHECKSIG
    script.append(0x21)
    script.extend(bytes.fromhex(DERIVED_PUBKEY_HEX))
    script.append(OP_CHECKSIG)

    # Push each field using minimal encoding
    for field in FIELDS:
        script.extend(_minimal_push(field))

    # Push the data signature
    script.extend(_minimal_push(DATA_SIG))

    # Drop sequence: 4 items total -> 2x OP_2DROP
    script.append(OP_2DROP)
    script.append(OP_2DROP)

    return script.hex()


EXPECTED_HEX = _build_expected_hex()


# ===========================================================================
# 1. _minimal_push() edge case tests
# ===========================================================================
class TestMinimalPush(unittest.TestCase):
    """BIP-62 minimal push encoding edge cases."""

    # -- OP_0 cases ---------------------------------------------------------
    def test_empty_data(self):
        self.assertEqual(_minimal_push(b""), bytes([0x00]))

    def test_single_zero_byte(self):
        self.assertEqual(_minimal_push(b"\x00"), bytes([0x00]))

    # -- OP_1 through OP_16 ------------------------------------------------
    def test_single_bytes_1_through_16(self):
        for v in range(1, 17):
            result = _minimal_push(bytes([v]))
            self.assertEqual(result, bytes([0x50 + v]),
                             f"Failed for value {v}")

    # -- OP_1NEGATE ---------------------------------------------------------
    def test_0x81_maps_to_op_1negate(self):
        self.assertEqual(_minimal_push(bytes([0x81])), bytes([0x4F]))

    # -- Direct push: single byte NOT in special range ----------------------
    def test_single_byte_0x11(self):
        # 0x11 == 17, not in 1-16 range
        self.assertEqual(_minimal_push(bytes([0x11])), bytes([0x01, 0x11]))

    def test_single_byte_0x80(self):
        # 0x80 is not 0x00, not 1-16, not 0x81
        self.assertEqual(_minimal_push(bytes([0x80])), bytes([0x01, 0x80]))

    def test_single_byte_0xff(self):
        self.assertEqual(_minimal_push(bytes([0xFF])), bytes([0x01, 0xFF]))

    # -- Direct push: lengths 2-75 -----------------------------------------
    def test_length_2(self):
        data = bytes([0xDE, 0xAD])
        result = _minimal_push(data)
        self.assertEqual(result, bytes([2]) + data)

    def test_length_75(self):
        data = bytes(range(75))
        result = _minimal_push(data)
        self.assertEqual(result[0], 75)
        self.assertEqual(result[1:], data)

    # -- OP_PUSHDATA1: lengths 76-255 --------------------------------------
    def test_length_76(self):
        data = b"\xAB" * 76
        result = _minimal_push(data)
        self.assertEqual(result[0], OP_PUSHDATA1)
        self.assertEqual(result[1], 76)
        self.assertEqual(result[2:], data)

    def test_length_255(self):
        data = b"\xCD" * 255
        result = _minimal_push(data)
        self.assertEqual(result[0], OP_PUSHDATA1)
        self.assertEqual(result[1], 255)
        self.assertEqual(result[2:], data)

    # -- OP_PUSHDATA2: lengths 256-65535 ------------------------------------
    def test_length_256(self):
        data = b"\xEF" * 256
        result = _minimal_push(data)
        self.assertEqual(result[0], OP_PUSHDATA2)
        expected_len = struct.pack("<H", 256)
        self.assertEqual(result[1:3], expected_len)
        self.assertEqual(result[3:], data)

    def test_length_65535(self):
        data = b"\x01" * 65535
        result = _minimal_push(data)
        self.assertEqual(result[0], OP_PUSHDATA2)
        expected_len = struct.pack("<H", 65535)
        self.assertEqual(result[1:3], expected_len)
        self.assertEqual(result[3:], data)

    # -- OP_PUSHDATA4: length > 65535 (sanity, but expensive) ---------------
    def test_length_65536(self):
        data = b"\x00" * 65536
        result = _minimal_push(data)
        self.assertEqual(result[0], 0x4E)  # OP_PUSHDATA4
        expected_len = struct.pack("<I", 65536)
        self.assertEqual(result[1:5], expected_len)
        self.assertEqual(result[5:], data)


# ===========================================================================
# 2. build_pushdrop_locking_script() with mock wallet
# ===========================================================================
class TestBuildPushDropLockingScript(unittest.TestCase):
    """Test full locking script construction with deterministic mock wallet."""

    def _make_mock_wallet(self, pubkey_hex: str, sig_bytes: bytes) -> MagicMock:
        wallet = MagicMock()
        wallet.get_public_key.return_value = {"publicKey": pubkey_hex}
        wallet.create_signature.return_value = {"signature": list(sig_bytes)}
        return wallet

    def test_shared_test_vector(self):
        """The canonical cross-language test vector."""
        wallet = self._make_mock_wallet(DERIVED_PUBKEY_HEX, DATA_SIG)
        result = build_pushdrop_locking_script(
            wallet,
            fields=list(FIELDS),
            protocol_id=[2, "test protocol"],
            key_id="test-key",
            counterparty="anyone",
        )
        self.assertEqual(result, EXPECTED_HEX)

    def test_wallet_called_correctly(self):
        """Verify that get_public_key and create_signature are called."""
        wallet = self._make_mock_wallet(DERIVED_PUBKEY_HEX, DATA_SIG)
        build_pushdrop_locking_script(
            wallet,
            fields=list(FIELDS),
            protocol_id=[2, "test protocol"],
            key_id="test-key",
            counterparty="anyone",
        )
        wallet.get_public_key.assert_called_once()
        wallet.create_signature.assert_called_once()

        # Verify the signature was over the concatenation of all fields
        call_args = wallet.create_signature.call_args[0][0]
        expected_data = list(b"field-zero" + b"field-one" + b"field-two")
        self.assertEqual(call_args["data"], expected_data)

    def test_single_field_produces_one_2drop(self):
        """1 field + 1 sig = 2 items -> 1x OP_2DROP, 0x OP_DROP."""
        wallet = self._make_mock_wallet(DERIVED_PUBKEY_HEX, DATA_SIG)
        result_hex = build_pushdrop_locking_script(
            wallet,
            fields=[b"only-field"],
            protocol_id=[2, "test"],
            key_id="k",
            counterparty="anyone",
        )
        result_bytes = bytes.fromhex(result_hex)
        # Last bytes should be: OP_2DROP only (no OP_DROP)
        self.assertEqual(result_bytes[-1], OP_2DROP)
        self.assertNotEqual(result_bytes[-2], OP_DROP)

    def test_empty_field(self):
        """An empty field should be encoded as OP_0 (0x00)."""
        wallet = self._make_mock_wallet(DERIVED_PUBKEY_HEX, DATA_SIG)
        result_hex = build_pushdrop_locking_script(
            wallet,
            fields=[b""],
            protocol_id=[2, "test"],
            key_id="k",
            counterparty="anyone",
        )
        result_bytes = bytes.fromhex(result_hex)
        # After the lock prefix (33+1+1 = 35 bytes), the first push should be OP_0
        self.assertEqual(result_bytes[35], 0x00)


# ===========================================================================
# 3. Drop sequence calculation
# ===========================================================================
class TestDropSequence(unittest.TestCase):
    """Verify the OP_2DROP / OP_DROP tail for various item counts."""

    def _count_drops(self, n_fields: int) -> tuple[int, int]:
        """Build a script with n_fields fields and count trailing drops."""
        wallet = MagicMock()
        wallet.get_public_key.return_value = {"publicKey": DERIVED_PUBKEY_HEX}
        wallet.create_signature.return_value = {"signature": list(DATA_SIG)}

        fields = [b"x" * 10] * n_fields
        result_hex = build_pushdrop_locking_script(
            wallet,
            fields=fields,
            protocol_id=[2, "test"],
            key_id="k",
            counterparty="anyone",
        )
        result_bytes = bytes.fromhex(result_hex)

        # Count trailing OP_2DROP (0x6d) and OP_DROP (0x75) bytes
        n_2drop = 0
        n_drop = 0
        i = len(result_bytes) - 1
        while i >= 0:
            if result_bytes[i] == OP_2DROP:
                n_2drop += 1
                i -= 1
            elif result_bytes[i] == OP_DROP:
                n_drop += 1
                i -= 1
            else:
                break
        return n_2drop, n_drop

    def test_8_fields_gives_4x2drop_1xdrop(self):
        """8 fields + 1 sig = 9 items -> 4x OP_2DROP + 1x OP_DROP."""
        n_2drop, n_drop = self._count_drops(8)
        self.assertEqual(n_2drop, 4)
        self.assertEqual(n_drop, 1)

    def test_9_fields_gives_5x2drop(self):
        """9 fields + 1 sig = 10 items -> 5x OP_2DROP, 0x OP_DROP."""
        n_2drop, n_drop = self._count_drops(9)
        self.assertEqual(n_2drop, 5)
        self.assertEqual(n_drop, 0)

    def test_3_fields_gives_2x2drop(self):
        """3 fields + 1 sig = 4 items -> 2x OP_2DROP."""
        n_2drop, n_drop = self._count_drops(3)
        self.assertEqual(n_2drop, 2)
        self.assertEqual(n_drop, 0)

    def test_2_fields_gives_1x2drop_1xdrop(self):
        """2 fields + 1 sig = 3 items -> 1x OP_2DROP + 1x OP_DROP."""
        n_2drop, n_drop = self._count_drops(2)
        self.assertEqual(n_2drop, 1)
        self.assertEqual(n_drop, 1)

    def test_1_field_gives_1x2drop(self):
        """1 field + 1 sig = 2 items -> 1x OP_2DROP."""
        n_2drop, n_drop = self._count_drops(1)
        self.assertEqual(n_2drop, 1)
        self.assertEqual(n_drop, 0)


if __name__ == "__main__":
    unittest.main()

"""TEE attestation and BSV signing for the inference proxy.

Replaces the original Ethereum ECDSA + Ed25519 dual-signing system with
BRC-100 BSV signing via py-wallet-toolbox. The BSV key is generated inside
the CVM at startup and bound to the TDX hardware attestation.
"""
import json
import os
import hashlib

import pynvml
from dstack_sdk import DstackClient
from nv_attestation_sdk import attestation
from verifier import cc_admin

from app.logger import log
from app.wallet.bsv_wallet import (
    get_tee_public_key,
    get_report_data_for_attestation,
    sign_data,
    INFERENCE_SIGNING_PROTOCOL,
)
from app.attestation.anchor import get_attestation_id

GPU_ARCH = "HOPPER"
NO_GPU_MODE = os.getenv("GPU_NO_HW_MODE", "0").lower() in {"1", "true", "yes"}


def sign(content: str) -> str:
    """Sign content string with BRC-100. Returns hex-encoded DER signature."""
    data = content.encode("utf-8")
    sig_bytes = sign_data(data, key_id=get_attestation_id())
    return sig_bytes.hex()


def _collect_gpu_evidence(nonce_hex: str, no_gpu_mode: bool) -> list:
    if no_gpu_mode:
        log.info("GPU evidence no-GPU mode enabled; using canned evidence")
        return cc_admin.collect_gpu_evidence_remote(nonce_hex, no_gpu_mode=True)

    try:
        pynvml.nvmlInit()
        device_count = pynvml.nvmlDeviceGetCount()
        if device_count == 1:
            return cc_admin.collect_gpu_evidence_remote(nonce_hex)
        attester = attestation.Attestation()
        attester.set_name("HOPPER")
        attester.set_nonce(nonce_hex)
        attester.set_claims_version("2.0")
        attester.set_ocsp_nonce_disabled(True)
        attester.add_verifier(
            dev=attestation.Devices.GPU,
            env=attestation.Environment["REMOTE"],
            url=None,
            evidence="",
        )
        return attester.get_evidence(options={"ppcie_mode": False})
    except pynvml.NVMLError as error:
        log.error("NVML error while collecting GPU evidence: %s", error)
        raise Exception("NVML error during GPU evidence collection") from error
    except Exception as error:
        log.error("GPU evidence collection failed: %s", error)
        raise
    finally:
        try:
            pynvml.nvmlShutdown()
        except pynvml.NVMLError:
            pass


def _build_nvidia_payload(nonce_hex: str, evidences: list) -> str:
    data = {"nonce": nonce_hex, "evidence_list": evidences, "arch": GPU_ARCH}
    return json.dumps(data)


def generate_initial_attestation() -> dict | None:
    """
    Generate the initial TDX attestation at startup.
    Binds the BSV public key to the hardware via report_data.
    Returns a dict with fields needed by attestation/anchor.py, or None on failure.
    """
    try:
        report_data = get_report_data_for_attestation()
        client = DstackClient()
        quote_result = client.get_quote(report_data)
        event_log = json.loads(quote_result.event_log)

        # Parse MR values from event log for the attestation record
        mr_enclave = ""
        mr_signer = ""
        for entry in event_log if isinstance(event_log, list) else []:
            if isinstance(entry, dict):
                if "mr_enclave" in entry:
                    mr_enclave = entry["mr_enclave"]
                elif "mr_td" in entry:
                    mr_enclave = entry["mr_td"]
                if "mr_signer" in entry:
                    mr_signer = entry["mr_signer"]
                elif "mr_signer_seam" in entry:
                    mr_signer = entry["mr_signer_seam"]

        # Collect GPU evidence
        nonce_hex = os.urandom(32).hex()
        gpu_evidence = None
        gpu_evidence_hash = None
        try:
            gpu_evidence = _collect_gpu_evidence(nonce_hex, NO_GPU_MODE)
            if gpu_evidence:
                nvidia_payload = _build_nvidia_payload(nonce_hex, gpu_evidence)
                gpu_evidence_hash = hashlib.sha256(nvidia_payload.encode()).hexdigest()
        except Exception as e:
            log.error("GPU evidence collection failed during initial attestation: %s", e)

        return {
            "intel_quote": quote_result.quote,
            "event_log": event_log,
            "mr_enclave": mr_enclave,
            "mr_signer": mr_signer,
            "gpu_evidence_hash": gpu_evidence_hash,
            "info": client.info().model_dump(),
        }
    except Exception as e:
        log.error("Initial attestation failed: %s", e)
        return None


def generate_attestation(nonce: str | None = None) -> dict:
    """
    Generate a full attestation report (called by the /attestation/report endpoint).
    Returns the attestation dict for the API response.
    """
    tee_pubkey = get_tee_public_key()
    report_data = get_report_data_for_attestation()

    client = DstackClient()
    quote_result = client.get_quote(report_data)
    event_log = json.loads(quote_result.event_log)

    # Use provided nonce or generate one for GPU evidence
    nonce_hex = nonce if nonce else os.urandom(32).hex()
    gpu_evidence = _collect_gpu_evidence(nonce_hex, NO_GPU_MODE)
    nvidia_payload = None
    if gpu_evidence:
        nvidia_payload = _build_nvidia_payload(nonce_hex, gpu_evidence)

    info = client.info().model_dump()

    # Sign the attestation report itself
    report_content = f"{tee_pubkey}:{quote_result.quote[:64]}:{nonce_hex}"
    attestation_sig = sign(report_content)

    return dict(
        signing_identity_key=tee_pubkey,
        intel_quote=quote_result.quote,
        nvidia_payload=nvidia_payload,
        event_log=event_log,
        info=info,
        bsv_attestation_signature=attestation_sig,
        attestation_txid=get_attestation_id(),
    )


__all__ = [
    "sign",
    "generate_attestation",
    "generate_initial_attestation",
]

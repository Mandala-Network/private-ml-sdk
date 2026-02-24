import os
import time
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request

from .api import router as api_router
from .api.response.response import ok, error, http_exception
from .logger import log

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- Startup ---

    # 1. Initialize BSV wallet
    from app.wallet.bsv_wallet import init_wallet, get_tee_public_key, get_report_data_for_attestation
    wallet, tee_pubkey = init_wallet()
    logger.info(f"BSV wallet initialized: {tee_pubkey}")

    # 2. Request funding from Mandala Node
    import requests as sync_requests
    callback_url = os.environ.get("MANDALA_NODE_CALLBACK_URL")
    if callback_url:
        try:
            from bsv.keys import PublicKey
            address = PublicKey.from_hex(tee_pubkey).to_address()
            sync_requests.post(
                f"{callback_url.rstrip('/')}/fund-proxy",
                json={"address": address, "publicKey": tee_pubkey, "amount": 1000},
                timeout=15,
            )
            logger.info("Requested funding from Mandala Node")
            time.sleep(5)
        except Exception as e:
            logger.error(f"Failed to request funding: {e}")

    # 3. Get TDX attestation quote (binds BSV key to hardware)
    from app.quote.quote import generate_initial_attestation
    attestation_data = generate_initial_attestation()

    # 4. Publish attestation PushDrop token
    if attestation_data:
        from app.attestation.anchor import publish_attestation
        await publish_attestation(
            intel_quote_hex=attestation_data["intel_quote"],
            mr_enclave=attestation_data["mr_enclave"],
            mr_signer=attestation_data["mr_signer"],
            gpu_evidence_hash=attestation_data.get("gpu_evidence_hash"),
        )

    # 5. Start receipt batch timer
    from app.receipts.accumulator import start_batch_timer
    start_batch_timer()

    yield

    # --- Shutdown ---
    logger.info("Shutting down TEE inference proxy")


app = FastAPI(lifespan=lifespan)
app.include_router(api_router)


@app.get("/")
async def root():
    return ok()


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    if isinstance(exc, HTTPException):
        log.error(f"HTTPException: {exc.detail}")
        return http_exception(exc.status_code, exc.detail)

    log.error(f"Unhandled exception: {exc}")
    return error(
        status_code=500,
        message=str(exc),
        type=type(exc).__name__,
        param=None,
        code=None,
    )

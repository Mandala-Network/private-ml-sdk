import json
import os
from hashlib import sha256
from typing import Optional

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Header, Query
from fastapi.responses import (
    JSONResponse,
    PlainTextResponse,
    StreamingResponse,
    Response,
)

from app.api.helper.auth import verify_authorization_header
from app.api.response.response import (
    not_found,
    unexpect_error,
)
from app.cache.cache import cache
from app.logger import log
from app.quote.quote import sign, generate_attestation
from app.wallet.bsv_wallet import get_tee_public_key, INFERENCE_SIGNING_PROTOCOL
from app.attestation.anchor import get_attestation_id
from app.receipts.accumulator import add_receipt

router = APIRouter(tags=["openai"])

VLLM_BASE_URL = os.getenv("VLLM_BASE_URL", "http://vllm:8000")
VLLM_URL = f"{VLLM_BASE_URL}/v1/chat/completions"
VLLM_COMPLETIONS_URL = f"{VLLM_BASE_URL}/v1/completions"
VLLM_METRICS_URL = f"{VLLM_BASE_URL}/metrics"
VLLM_MODELS_URL = f"{VLLM_BASE_URL}/v1/models"
TIMEOUT = 60 * 10

COMMON_HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}


def hash(payload: str):
    return sha256(payload.encode()).hexdigest()


def sign_chat(text: str) -> dict:
    """Sign inference text with BRC-100 and return cache entry."""
    attestation_id = get_attestation_id()
    return dict(
        text=text,
        signature=sign(text),
        signing_identity_key=get_tee_public_key(),
        protocolID=INFERENCE_SIGNING_PROTOCOL,
        keyID=attestation_id,
    )


async def stream_vllm_response(
    url: str,
    request_body: bytes,
    modified_request_body: bytes,
    request_hash: Optional[str] = None,
):
    """
    Handle streaming vllm request.
    Args:
        request_body: The original request body
        modified_request_body: The modified enhanced request body
        request_hash: Optional hash from request header (X-Request-Hash)
    Returns:
        A streaming response
    """
    if request_hash:
        request_sha256 = request_hash
        log.info(f"Using client-provided request hash: {request_sha256}")
    else:
        request_sha256 = sha256(request_body).hexdigest()
        log.debug(f"Calculated request hash: {request_sha256}")

    chat_id = None
    h = sha256()

    async def generate_stream(response):
        nonlocal chat_id, h
        async for chunk in response.aiter_text():
            h.update(chunk.encode())
            if not chat_id:
                data = chunk.strip("data: ").strip()
                if not data or data == "[DONE]":
                    continue
                try:
                    chunk_data = json.loads(data)
                    chat_id = chunk_data.get("id")
                except Exception as e:
                    error_message = f"Failed to parse the first chunk: {e}\n The original data is: {data}"
                    log.error(error_message)
                    raise Exception(error_message)

            yield chunk

        response_sha256 = h.hexdigest()
        if chat_id:
            signed = sign_chat(f"{request_sha256}:{response_sha256}")
            cache.set_chat(chat_id, json.dumps(signed))
            add_receipt(request_sha256, response_sha256, chat_id)
        else:
            error_message = "Chat id could not be extracted from the response"
            log.error(error_message)
            raise Exception(error_message)

    client = httpx.AsyncClient(timeout=httpx.Timeout(TIMEOUT), headers=COMMON_HEADERS)
    req = client.build_request("POST", url, content=modified_request_body)
    response = await client.send(req, stream=True)

    if response.status_code != 200:
        error_content = await response.aread()
        await response.aclose()
        await client.aclose()

        return Response(
            content=error_content,
            status_code=response.status_code,
            headers=response.headers,
        )

    return StreamingResponse(
        generate_stream(response),
        background=BackgroundTasks([response.aclose, client.aclose]),
        media_type="text/event-stream",
        headers={
            "X-Signing-Identity-Key": get_tee_public_key(),
            "X-Attestation-Txid": get_attestation_id(),
        },
    )


async def non_stream_vllm_response(
    url: str,
    request_body: bytes,
    modified_request_body: bytes,
    request_hash: Optional[str] = None,
):
    """
    Handle non-streaming responses.
    Args:
        request_body: The original request body
        modified_request_body: The modified enhanced request body
        request_hash: Optional hash from request header (X-Request-Hash)
    Returns:
        The response data
    """
    if request_hash:
        request_sha256 = request_hash
        log.info(f"Using client-provided request hash: {request_sha256}")
    else:
        request_sha256 = sha256(request_body).hexdigest()
        log.debug(f"Calculated request hash: {request_sha256}")

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(TIMEOUT), headers=COMMON_HEADERS
    ) as client:
        response = await client.post(url, content=modified_request_body)
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.text)

        response_data = response.json()
        chat_id = response_data.get("id")
        if chat_id:
            response_sha256 = sha256(response.content).hexdigest()
            signed = sign_chat(f"{request_sha256}:{response_sha256}")
            cache.set_chat(chat_id, json.dumps(signed))
            add_receipt(request_sha256, response_sha256, chat_id)
        else:
            raise Exception("Chat id could not be extracted from the response")

        return response_data


def strip_empty_tool_calls(payload: dict) -> dict:
    """
    Strip empty tool calls from the payload.
    Fix for: https://github.com/vllm-project/vllm/pull/14054
    """
    if "messages" not in payload:
        return payload

    filtered_messages = []
    for message in payload["messages"]:
        if (
            "tool_calls" in message
            and isinstance(message["tool_calls"], list)
            and len(message["tool_calls"]) == 0
        ):
            del message["tool_calls"]
        filtered_messages.append(message)

    payload["messages"] = filtered_messages
    return payload


# Get attestation report
@router.get("/attestation/report", dependencies=[Depends(verify_authorization_header)])
async def attestation_report(
    request: Request,
    nonce: str | None = Query(None),
    signing_identity_key: str | None = Query(None),
):
    tee_pubkey = get_tee_public_key()

    # If signing_identity_key is specified and doesn't match, return 404
    if signing_identity_key and tee_pubkey.lower() != signing_identity_key.lower():
        raise HTTPException(status_code=404, detail="Signing identity key not found on this server")

    try:
        report = generate_attestation(nonce)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    resp = dict(report)
    resp["all_attestations"] = [report]
    return resp


# VLLM Chat completions
@router.post("/chat/completions", dependencies=[Depends(verify_authorization_header)])
async def chat_completions(
    request: Request,
    x_request_hash: Optional[str] = Header(None, alias="X-Request-Hash"),
):
    request_body = await request.body()
    request_json = json.loads(request_body)
    modified_json = strip_empty_tool_calls(request_json)

    is_stream = modified_json.get("stream", False)

    modified_request_body = json.dumps(modified_json).encode("utf-8")
    if is_stream:
        return await stream_vllm_response(
            VLLM_URL, request_body, modified_request_body, x_request_hash
        )
    else:
        response_data = await non_stream_vllm_response(
            VLLM_URL, request_body, modified_request_body, x_request_hash
        )
        return JSONResponse(
            content=response_data,
            headers={
                "X-Signing-Identity-Key": get_tee_public_key(),
                "X-Attestation-Txid": get_attestation_id(),
            },
        )


# VLLM completions
@router.post("/completions", dependencies=[Depends(verify_authorization_header)])
async def completions(
    request: Request,
    x_request_hash: Optional[str] = Header(None, alias="X-Request-Hash"),
):
    request_body = await request.body()
    request_json = json.loads(request_body)
    modified_json = strip_empty_tool_calls(request_json)

    is_stream = modified_json.get("stream", False)

    modified_request_body = json.dumps(modified_json).encode("utf-8")
    if is_stream:
        return await stream_vllm_response(
            VLLM_COMPLETIONS_URL, request_body, modified_request_body, x_request_hash
        )
    else:
        response_data = await non_stream_vllm_response(
            VLLM_COMPLETIONS_URL, request_body, modified_request_body, x_request_hash
        )
        return JSONResponse(
            content=response_data,
            headers={
                "X-Signing-Identity-Key": get_tee_public_key(),
                "X-Attestation-Txid": get_attestation_id(),
            },
        )


# Get signature for chat_id
@router.get("/signature/{chat_id}", dependencies=[Depends(verify_authorization_header)])
async def signature(request: Request, chat_id: str):
    cache_value = cache.get_chat(chat_id)
    if cache_value is None:
        return not_found("Chat id not found or expired")

    try:
        value = json.loads(cache_value)
    except Exception as e:
        log.error(f"Failed to parse the cache value: {cache_value} {e}")
        return unexpect_error("Failed to parse the cache value", e)

    return dict(
        text=value.get("text"),
        signature=value.get("signature"),
        signing_identity_key=value.get("signing_identity_key"),
        protocolID=value.get("protocolID"),
        keyID=value.get("keyID"),
    )


# Metrics of vLLM instance
@router.get("/metrics")
async def metrics(request: Request):
    async with httpx.AsyncClient(timeout=httpx.Timeout(TIMEOUT)) as client:
        response = await client.get(VLLM_METRICS_URL)
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.text)
        return PlainTextResponse(response.text)


@router.get("/models")
async def models(request: Request):
    async with httpx.AsyncClient(timeout=httpx.Timeout(TIMEOUT)) as client:
        response = await client.get(VLLM_MODELS_URL)
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.text)
        return JSONResponse(content=response.json())

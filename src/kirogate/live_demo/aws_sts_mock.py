"""Mock AWS STS service for local testing.

Emulates the AssumeRole API endpoint so we can test the full
KiroGate credential minting flow without real AWS.

This replaces LocalStack/moto for local development.
In production, point STS_ENDPOINT to real AWS STS.

Endpoints:
    POST / (with Action=AssumeRole) → returns temporary credentials
"""

from __future__ import annotations

import hashlib
import time
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Form, Request
from fastapi.responses import Response

router = APIRouter(tags=["aws-sts-mock"])


def _generate_credentials(role_arn: str, session_name: str, duration: int = 900):
    """Generate mock AWS temporary credentials."""
    # Generate realistic-looking but fake credentials
    seed = f"{role_arn}:{session_name}:{time.time()}"
    h = hashlib.sha256(seed.encode()).hexdigest()

    access_key = f"ASIA{h[:16].upper()}"
    secret_key = h[:40]
    session_token = f"FwoGZXIvYXdzE{h}"

    expiration = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    return {
        "access_key_id": access_key,
        "secret_access_key": secret_key,
        "session_token": session_token,
        "expiration": expiration,
    }


@router.post("/sts")
async def assume_role(request: Request):
    """Mock AWS STS AssumeRole endpoint.

    Accepts the same form parameters as real AWS STS.
    Returns XML response matching AWS STS format.
    """
    body = await request.body()
    params = dict(x.split("=", 1) for x in body.decode().split("&") if "=" in x)

    action = params.get("Action", "")
    role_arn = params.get("RoleArn", "arn:aws:iam::123456789012:role/MockRole")
    session_name = params.get("RoleSessionName", "mock-session")
    duration = int(params.get("DurationSeconds", "900"))

    if action != "AssumeRole":
        return Response(
            content=f"""<ErrorResponse><Error><Code>InvalidAction</Code>
            <Message>Action {action} not supported</Message></Error></ErrorResponse>""",
            media_type="text/xml",
            status_code=400,
        )

    creds = _generate_credentials(role_arn, session_name, duration)
    request_id = str(uuid.uuid4())

    # Return XML matching real AWS STS response format
    xml_response = f"""<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <AssumedRoleUser>
      <AssumedRoleId>AROA{hashlib.md5(role_arn.encode()).hexdigest()[:16].upper()}:{session_name}</AssumedRoleId>
      <Arn>{role_arn}/{session_name}</Arn>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>{creds['access_key_id']}</AccessKeyId>
      <SecretAccessKey>{creds['secret_access_key']}</SecretAccessKey>
      <SessionToken>{creds['session_token']}</SessionToken>
      <Expiration>{creds['expiration']}</Expiration>
    </Credentials>
    <PackedPolicySize>6</PackedPolicySize>
  </AssumeRoleResult>
  <ResponseMetadata>
    <RequestId>{request_id}</RequestId>
  </ResponseMetadata>
</AssumeRoleResponse>"""

    return Response(content=xml_response, media_type="text/xml")

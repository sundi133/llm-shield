"""Send one transactional email through Resend (docs/specs/self-serve-signup.md).

POST https://api.resend.com/emails with RESEND_API_KEY, from SHIELD_SIGNUP_FROM
(a sender on a domain verified in Resend). Plain text and HTML, no tracking
pixels and no tracked links: a sign-in link must reach the user as written.
"""

from __future__ import annotations

import logging
import os

import httpx

logger = logging.getLogger("votal.email")

RESEND_URL = "https://api.resend.com/emails"
TIMEOUT_S = 10


class EmailError(Exception):
    """The email could not be sent; the caller says so and keeps nothing."""


def configured() -> bool:
    return bool(os.environ.get("RESEND_API_KEY", "").strip()
                and os.environ.get("SHIELD_SIGNUP_FROM", "").strip())


async def send(to: str, subject: str, text: str, html: str) -> None:
    key = os.environ.get("RESEND_API_KEY", "").strip()
    sender = os.environ.get("SHIELD_SIGNUP_FROM", "").strip()
    if not key or not sender:
        raise EmailError("email is not configured (RESEND_API_KEY, SHIELD_SIGNUP_FROM)")
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT_S) as client:
            resp = await client.post(RESEND_URL, headers={"Authorization": f"Bearer {key}"},
                                     json={"from": sender, "to": [to], "subject": subject,
                                           "text": text, "html": html})
    except httpx.HTTPError as e:
        logger.warning("email not sent: %s", type(e).__name__)
        raise EmailError("the email service could not be reached") from e
    if resp.status_code >= 300:
        # The body may name the recipient; log the status only.
        logger.warning("email not sent: Resend answered HTTP %s", resp.status_code)
        raise EmailError(f"the email service answered HTTP {resp.status_code}")

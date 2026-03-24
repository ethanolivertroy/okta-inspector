"""Okta API client with pagination and rate-limit handling."""

from __future__ import annotations

import logging
import re
import time
from typing import Any

import requests

logger = logging.getLogger(__name__)


class OktaClient:
    """Low-level HTTP client for the Okta v1 API.

    Handles:
    - SSWS and OAuth Bearer token types
    - Paginated list responses (``Link`` header)
    - 429 rate-limit backoff (``X-Rate-Limit-Reset``)
    - Proactive pause when ``X-Rate-Limit-Remaining`` < 10
    """

    def __init__(
        self,
        domain: str,
        token: str,
        *,
        page_size: int = 200,
        max_pages: int = 10,
    ) -> None:
        self.domain = domain.rstrip("/")
        self.base_url = f"https://{self.domain}/api/v1"
        self.page_size = page_size
        self.max_pages = max_pages
        self.api_call_count = 0

        # Build auth header
        if token.startswith("Bearer "):
            auth_value = token
        elif token.startswith("SSWS "):
            auth_value = token
        else:
            auth_value = f"SSWS {token}"

        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": auth_value,
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        *,
        max_pages: int | None = None,
    ) -> list[dict[str, Any]] | dict[str, Any] | None:
        """Paginated GET.  Returns a list, a single dict, or ``None`` on failure."""
        url = f"{self.base_url}{endpoint}"
        all_results: list[dict[str, Any]] = []
        page_count = 0
        effective_max = max_pages if max_pages is not None else self.max_pages

        while url and page_count < effective_max:
            page_count += 1
            self.api_call_count += 1

            try:
                response = self._session.get(
                    url,
                    params=params if page_count == 1 else None,
                )

                if response.status_code == 429:
                    self._handle_rate_limit(response, page_count)
                    continue

                response.raise_for_status()
                self._check_remaining(response)

                data = response.json()

                if isinstance(data, list):
                    all_results.extend(data)
                    url = self._next_link(response)
                else:
                    return data  # single-object response

            except requests.exceptions.RequestException as e:
                logger.error("API request failed for %s: %s", endpoint, e)
                return all_results if all_results else None

        return all_results if all_results else None

    def test_connection(self) -> bool:
        """Quick smoke test — fetch one user."""
        logger.info("Testing API connection...")
        try:
            result = self.get("/users?limit=1")
            if result is not None:
                logger.info("API connection successful!")
                return True
            logger.error("API connection failed — no data returned")
            return False
        except Exception as e:
            logger.error("API connection failed: %s", e)
            return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _handle_rate_limit(self, response: requests.Response, attempt: int) -> None:
        reset_header = response.headers.get("X-Rate-Limit-Reset")
        if reset_header:
            wait = max(int(reset_header) - int(time.time()) + 1, 1)
        else:
            wait = min(2**attempt, 60)
        logger.warning("Rate limit hit. Waiting %d seconds...", wait)
        time.sleep(wait)

    def _check_remaining(self, response: requests.Response) -> None:
        remaining = response.headers.get("X-Rate-Limit-Remaining")
        if remaining and int(remaining) < 10:
            reset_header = response.headers.get("X-Rate-Limit-Reset")
            if reset_header:
                wait = max(int(reset_header) - int(time.time()) + 1, 0)
                if wait > 0:
                    logger.warning("Rate limit nearly exhausted. Pausing %d seconds...", wait)
                    time.sleep(wait)

    @staticmethod
    def _next_link(response: requests.Response) -> str | None:
        link_header = response.headers.get("Link", "")
        if not link_header:
            return None
        for part in link_header.split(","):
            if 'rel="next"' in part:
                m = re.search(r"<([^>]+)>", part)
                if m:
                    return m.group(1)
        return None

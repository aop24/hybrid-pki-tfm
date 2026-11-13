import ssl

import httpx

from app.core.config import settings


class EJBCAClient:

    def __init__(self):
        self.base_url = settings.EJBCA_BASE_URL.rstrip("/")
        self.v2_base_url = settings.EJBCA_V2_BASE_URL.rstrip("/")
        self.timeout = settings.EJBCA_TIMEOUT

        self.ssl_context = ssl.create_default_context(
            cafile=settings.EJBCA_CA_CERT
        )

        self.ssl_context.load_cert_chain(
            certfile=settings.EJBCA_CLIENT_CERT,
            keyfile=settings.EJBCA_CLIENT_KEY
        )

        self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.ssl_context.maximum_version = ssl.TLSVersion.TLSv1_2

    async def get(self, endpoint: str):
        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        async with httpx.AsyncClient(
            verify=self.ssl_context,
            timeout=self.timeout
        ) as client:

            response = await client.get(url)
            response.raise_for_status()

            return response.json()

    async def post(self, endpoint: str, payload: dict):
        url = f"{self.v2_base_url}/{endpoint.lstrip('/')}"

        async with httpx.AsyncClient(
            verify=self.ssl_context,
            timeout=self.timeout
        ) as client:

            response = await client.post(
                url,
                json=payload
            )

            response.raise_for_status()

            return response.json()

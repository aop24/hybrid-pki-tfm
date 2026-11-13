from datetime import datetime, timezone
from math import ceil

from app.services.ejbca.client import EJBCAClient


class EJBCAService:

    CERTIFICATE_STATUSES = {
        0: "UNASSIGNED",
        10: "INACTIVE",
        11: "ROLLOVER_PENDING",
        20: "ACTIVE",
        21: "NOTIFIED_ABOUT_EXPIRATION",
        40: "REVOKED",
        60: "ARCHIVED",
    }

    # Estados que formarán parte del inventario del panel.
    INVENTORY_STATUSES = (
        "CERT_ACTIVE",
        "CERT_REVOKED",
    )

    # Tamaño de bloque para recuperar el inventario completo de EJBCA.
    FETCH_PAGE_SIZE = 100

    def __init__(self):
        self.client = EJBCAClient()

    async def get_status(self):
        return await self.client.get("ca/status")

    async def get_certificate_authorities(self):
        response = await self.client.get("ca")
        return response.get("certificate_authorities", [])

    @staticmethod
    def _timestamp_to_iso(value):
        if value is None or value == -1:
            return None

        try:
            timestamp = int(value) / 1000

            return datetime.fromtimestamp(
                timestamp,
                tz=timezone.utc
            ).isoformat()

        except (ValueError, TypeError, OverflowError, OSError):
            return None

    @classmethod
    def _get_validity_status(cls, not_before, expire_date):
        now = datetime.now(timezone.utc)

        start = cls._timestamp_to_iso(not_before)
        expiration = cls._timestamp_to_iso(expire_date)

        if start:
            start_date = datetime.fromisoformat(start)

            if now < start_date:
                return "NOT_YET_VALID"

        if expiration:
            expiration_date = datetime.fromisoformat(expiration)

            if now >= expiration_date:
                return "EXPIRED"

        return "VALID"

    @classmethod
    def _normalize_certificate(cls, certificate):
        status_code = certificate.get("status")

        try:
            status_code = int(status_code)
        except (ValueError, TypeError):
            status_code = None

        not_before = certificate.get("notBefore")
        expire_date = certificate.get("expireDate")

        return {
            "serial_number": certificate.get("serialNumber"),
            "subject_dn": certificate.get("subjectDN"),
            "issuer_dn": certificate.get("issuerDN"),
            "username": certificate.get("username"),

            "status_code": status_code,
            "status": cls.CERTIFICATE_STATUSES.get(
                status_code,
                "UNKNOWN"
            ),

            "validity_status": cls._get_validity_status(
                not_before,
                expire_date
            ),

            "certificate_profile": certificate.get(
                "certificateProfile"
            ),
            "certificate_profile_id": certificate.get(
                "certificateProfileId"
            ),

            "end_entity_profile": certificate.get(
                "endEntityProfile"
            ),
            "end_entity_profile_id": certificate.get(
                "endEntityProfileId"
            ),

            "not_before": cls._timestamp_to_iso(not_before),
            "expires_at": cls._timestamp_to_iso(expire_date),

            "revocation_date": cls._timestamp_to_iso(
                certificate.get("revocationDate")
            ),

            "revocation_reason": certificate.get(
                "revocationReason"
            ),

            "fingerprint": certificate.get("fingerprint"),
            "ca_fingerprint": certificate.get("cAFingerprint"),
            "subject_key_id": certificate.get("subjectKeyId"),
            "subject_alt_name": certificate.get("subjectAltName"),

            "certificate_type": certificate.get("type"),
            "tag": certificate.get("tag"),
        }

    async def _search_certificates(self, status, page, page_size):
        payload = {
            "pagination": {
                "page_size": page_size,
                "current_page": page
            },
            "criteria": [
                {
                    "property": "STATUS",
                    "value": status,
                    "operation": "EQUAL"
                }
            ]
        }

        return await self.client.post(
            "certificate/search",
            payload
        )

    async def _get_certificate_total(self, status):
        response = await self._search_certificates(
            status=status,
            page=-1,
            page_size=self.FETCH_PAGE_SIZE
        )

        pagination = response.get("pagination_summary", {})

        return int(pagination.get("total_certs", 0))

    async def _get_all_certificates_by_status(self, status):
        total = await self._get_certificate_total(status)

        if total == 0:
            return []

        total_pages = ceil(total / self.FETCH_PAGE_SIZE)
        certificates = []

        for page in range(1, total_pages + 1):
            response = await self._search_certificates(
                status=status,
                page=page,
                page_size=self.FETCH_PAGE_SIZE
            )

            certificates.extend(
                response.get("certificates", [])
            )

        return certificates

    async def get_certificates(self, page=1, page_size=20):
        if page < 1:
            page = 1

        if page_size < 1:
            page_size = 20

        # Recuperamos tanto los certificados activos como los revocados.
        all_certificates = []

        for status in self.INVENTORY_STATUSES:
            certificates = await self._get_all_certificates_by_status(
                status
            )
            all_certificates.extend(certificates)

        # Evitamos duplicados por número de serie e issuer.
        unique_certificates = {}

        for certificate in all_certificates:
            key = (
                certificate.get("issuerDN"),
                certificate.get("serialNumber")
            )
            unique_certificates[key] = certificate

        all_certificates = list(unique_certificates.values())

        # Orden determinista para que la paginación sea estable.
        all_certificates.sort(
            key=lambda certificate: (
                str(certificate.get("subjectDN") or "").lower(),
                str(certificate.get("serialNumber") or "").lower()
            )
        )

        total = len(all_certificates)
        total_pages = ceil(total / page_size) if total else 0

        start = (page - 1) * page_size
        end = start + page_size

        selected_certificates = all_certificates[start:end]

        items = [
            self._normalize_certificate(certificate)
            for certificate in selected_certificates
        ]

        return {
            "items": items,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total": total,
                "total_pages": total_pages
            }
        }

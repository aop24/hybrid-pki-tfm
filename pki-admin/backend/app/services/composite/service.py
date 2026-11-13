import re
import subprocess

from datetime import datetime, timezone
from math import ceil
from pathlib import Path

from app.core.config import settings


class CompositeService:

    def __init__(self):
        self.index_path = Path(settings.COMPOSITE_SUB_INDEX)
        self.certs_dir = Path(settings.COMPOSITE_SUB_CERTS_DIR)
        self.openssl = settings.OPENSSL_BINARY

    @staticmethod
    def _parse_index_date(value):
        if not value:
            return None

        try:
            return datetime.strptime(
                value,
                "%y%m%d%H%M%SZ"
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    @staticmethod
    def _to_iso(value):
        return value.isoformat() if value else None

    def _read_index(self):
        if not self.index_path.is_file():
            raise FileNotFoundError(
                f"Composite index not found: {self.index_path}"
            )

        records = []

        for line_number, line in enumerate(
            self.index_path.read_text(encoding="utf-8").splitlines(),
            start=1
        ):
            if not line.strip():
                continue

            fields = line.split("\t")

            if len(fields) < 6:
                raise ValueError(
                    f"Invalid Composite index entry at line {line_number}"
                )

            status, expiry, revocation, serial, filename, subject = fields[:6]

            status = status.strip()
            serial = serial.strip().upper()

            if status not in {"V", "R", "E"}:
                continue

            if not re.fullmatch(r"[0-9A-Fa-f]+", serial):
                raise ValueError(
                    f"Invalid certificate serial at line {line_number}"
                )

            records.append({
                "index_status": status,
                "expires_at": self._parse_index_date(expiry),
                "revocation_info": revocation.strip(),
                "serial_number": serial,
                "subject_from_index": subject.strip(),
            })

        return records

    @staticmethod
    def _parse_openssl_date(value):
        if not value:
            return None

        try:
            parsed = datetime.strptime(
                value,
                "%b %d %H:%M:%S %Y GMT"
            )
            return parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    def _read_certificate(self, serial):
        certificate_path = self.certs_dir / f"{serial}.pem"

        if not certificate_path.is_file():
            raise FileNotFoundError(
                f"Certificate PEM not found for serial {serial}"
            )

        command = [
            self.openssl,
            "x509",
            "-in", str(certificate_path),
            "-noout",
            "-subject",
            "-issuer",
            "-serial",
            "-startdate",
            "-enddate",
            "-fingerprint",
            "-sha256",
            "-nameopt",
            "RFC2253",
            "-text",
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=settings.COMPOSITE_TIMEOUT,
            check=True
        )

        output = result.stdout
        values = {}

        for line in output.splitlines():
            line = line.strip()

            for field in (
                "subject=",
                "issuer=",
                "serial=",
                "notBefore=",
                "notAfter=",
                "sha256 Fingerprint="
            ):
                if line.startswith(field):
                    values[field[:-1]] = line[len(field):].strip()

        public_key_algorithm = None
        signature_algorithm = None

        for line in output.splitlines():
            line = line.strip()

            if line.startswith("Public Key Algorithm:"):
                public_key_algorithm = line.split(":", 1)[1].strip()

            elif (
                line.startswith("Signature Algorithm:")
                and signature_algorithm is None
            ):
                signature_algorithm = line.split(":", 1)[1].strip()

        not_before = self._parse_openssl_date(values.get("notBefore"))
        not_after = self._parse_openssl_date(values.get("notAfter"))

        return {
            "subject_dn": values.get("subject"),
            "issuer_dn": values.get("issuer"),
            "serial_number": values.get("serial"),
            "not_before": self._to_iso(not_before),
            "expires_at": self._to_iso(not_after),
            "fingerprint": values.get("sha256 Fingerprint"),
            "public_key_algorithm": public_key_algorithm,
            "signature_algorithm": signature_algorithm,
        }

    @staticmethod
    def _get_status(index_status, expires_at):
        if index_status == "R":
            return "REVOKED"

        if index_status == "E":
            return "EXPIRED"

        if expires_at and datetime.now(timezone.utc) >= expires_at:
            return "EXPIRED"

        return "ACTIVE"

    @classmethod
    def _get_revocation_info(cls, value):
        if not value:
            return None, None

        parts = value.split(",", 1)
        revocation_date = cls._parse_index_date(parts[0].strip())
        reason = parts[1].strip() if len(parts) > 1 else None

        return cls._to_iso(revocation_date), reason

    def _normalize_certificate(self, record):
        certificate = self._read_certificate(record["serial_number"])

        expiration = (
            datetime.fromisoformat(certificate["expires_at"])
            if certificate["expires_at"]
            else None
        )

        status = self._get_status(
            record["index_status"],
            expiration
        )

        revocation_date, revocation_reason = (
            self._get_revocation_info(record["revocation_info"])
        )

        return {
            **certificate,
            "model": "COMPOSITE",
            "source": "COMPOSITE",
            "ca_name": "TFM Sub CA Composite",
            "status": status,
            "index_status": record["index_status"],
            "revocation_date": revocation_date,
            "revocation_reason": revocation_reason,
            "subject_from_index": record["subject_from_index"],
        }

    def get_certificates(self, page=1, page_size=20):
        records = self._read_index()

        total = len(records)
        total_pages = ceil(total / page_size) if total else 0

        start = (page - 1) * page_size
        selected_records = records[start:start + page_size]

        items = [
            self._normalize_certificate(record)
            for record in selected_records
        ]

        return {
            "items": items,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total": total,
                "total_pages": total_pages,
            }
        }

    def get_summary(self):
        records = self._read_index()

        counts = {
            "ACTIVE": 0,
            "REVOKED": 0,
            "EXPIRED": 0,
        }

        for record in records:
            counts[self._get_status(
                record["index_status"],
                record["expires_at"]
            )] += 1

        return {
            "model": "COMPOSITE",
            "ca_name": "TFM Sub CA Composite",
            "total": len(records),
            "active": counts["ACTIVE"],
            "revoked": counts["REVOKED"],
            "expired": counts["EXPIRED"],
        }

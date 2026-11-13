from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "PKI Admin API"
    APP_VERSION: str = "0.1.0"
    API_PREFIX: str = "/api"

    HOST: str = "127.0.0.1"
    PORT: int = 8000

    CORS_ORIGINS: str = "http://localhost:5173"

    # EJBCA REST API
    EJBCA_BASE_URL: str = "https://localhost:8443/ejbca/ejbca-rest-api/v1"
    EJBCA_V2_BASE_URL: str = "https://localhost:8443/ejbca/ejbca-rest-api/v2"

    EJBCA_CA_CERT: str = "/path/to/managementca.crt"
    EJBCA_CLIENT_CERT: str = "/path/to/superadmin.crt"
    EJBCA_CLIENT_KEY: str = "/path/to/superadmin.key"

    EJBCA_TIMEOUT: float = 15.0

    # Composite PKI - solo lectura
    COMPOSITE_SUB_INDEX: str = "/path/to/composite/sub/index.txt"
    COMPOSITE_SUB_CERTS_DIR: str = "/path/to/composite/sub/newcerts"
    COMPOSITE_ROOT_CERT: str = "/path/to/composite/root/root-ca.crt"
    COMPOSITE_SUB_CA_CERT: str = "/path/to/composite/sub/sub-ca.crt"

    OPENSSL_BINARY: str = "/usr/bin/openssl"
    COMPOSITE_TIMEOUT: float = 10.0

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def cors_origins_list(self) -> list[str]:
        return [
            origin.strip()
            for origin in self.CORS_ORIGINS.split(",")
            if origin.strip()
        ]


settings = Settings()

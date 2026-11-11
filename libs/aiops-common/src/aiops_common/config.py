"""12-factor configuration: everything from environment variables (prefix ``AIOPS_``)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class KafkaSettings(BaseModel):
    backend: Literal["kafka", "memory"] = "kafka"
    bootstrap_servers: str = "localhost:9092"
    client_id: str = "aiops"
    security_protocol: Literal["PLAINTEXT", "SSL", "SASL_PLAINTEXT", "SASL_SSL"] = "PLAINTEXT"
    sasl_mechanism: Literal["PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"] | None = None
    sasl_username: str | None = None
    sasl_password: SecretStr | None = None
    linger_ms: int = 5
    compression_type: Literal["gzip"] | None = None
    max_poll_records: int = 500


class ServiceSettings(BaseSettings):
    """Base settings for every service.

    Nested keys use ``__``, e.g. ``AIOPS_KAFKA__BOOTSTRAP_SERVERS``.
    """

    model_config = SettingsConfigDict(
        env_prefix="AIOPS_", env_nested_delimiter="__", extra="ignore"
    )

    service_name: str = "aiops-service"
    service_version: str = "0.1.0"
    environment: str = "dev"
    log_level: str = "INFO"
    http_host: str = "0.0.0.0"  # noqa: S104 - containers bind all interfaces
    http_port: int = 8080
    otel_exporter_otlp_endpoint: str | None = None
    shutdown_grace_seconds: float = 25.0
    kafka: KafkaSettings = KafkaSettings()

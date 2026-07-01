import logging
import subprocess
from typing import Any


class SecretRedactionFilter(logging.Filter):
    def __init__(self) -> None:
        super().__init__()
        self._secrets: list[str] = []

    def set_secrets(self, secrets: list[str]) -> None:
        self._secrets = [secret for secret in secrets if secret]

    def _redact(self, value: Any) -> Any:
        if isinstance(value, str):
            for secret in self._secrets:
                value = value.replace(secret, '<redacted>')
            return value
        if isinstance(value, tuple):
            return tuple(self._redact(item) for item in value)
        if isinstance(value, list):
            return [self._redact(item) for item in value]
        if isinstance(value, dict):
            return {key: self._redact(item) for key, item in value.items()}
        return value

    def _redact_exception(self, exc: BaseException) -> BaseException:
        if isinstance(exc, subprocess.CalledProcessError):
            return subprocess.CalledProcessError(
                exc.returncode,
                self._redact(exc.cmd),
                output=self._redact(exc.output),
                stderr=self._redact(exc.stderr),
            )

        redacted_args = self._redact(exc.args)
        try:
            return type(exc)(*redacted_args)
        except Exception:
            return RuntimeError(self._redact(str(exc)))

    def _redact_record_fields(self, record: logging.LogRecord) -> None:
        for key, value in tuple(record.__dict__.items()):
            if key in {'msg', 'args', 'exc_info', 'exc_text', 'message'}:
                continue
            record.__dict__[key] = self._redact(value)

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self._redact(record.msg)
        record.args = self._redact(record.args)
        if isinstance(record.msg, str):
            record.msg = self._redact(record.getMessage())
            record.args = ()
        if record.exc_info:
            exc_type, exc_value, exc_traceback = record.exc_info
            if exc_value is not None:
                record.exc_info = (exc_type, self._redact_exception(exc_value), exc_traceback)
        self._redact_record_fields(record)
        if hasattr(record, 'exc_text'):
            record.exc_text = None
        return True


def install_log_redaction_filter(secrets: list[str]) -> SecretRedactionFilter:
    for logger_name in ('', 'sanic.root', 'sanic.error', 'sanic.access'):
        target_logger = logging.getLogger(logger_name)
        for existing_filter in target_logger.filters:
            if isinstance(existing_filter, SecretRedactionFilter):
                existing_filter.set_secrets(secrets)
                return existing_filter
    redaction_filter = SecretRedactionFilter()
    redaction_filter.set_secrets(secrets)
    for logger_name in ('', 'sanic.root', 'sanic.error', 'sanic.access'):
        target_logger = logging.getLogger(logger_name)
        target_logger.addFilter(redaction_filter)
    return redaction_filter

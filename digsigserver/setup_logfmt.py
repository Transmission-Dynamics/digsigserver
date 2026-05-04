import logging
import sys
from datetime import datetime, UTC

STANDARD_LOG_RECORD_KEYS = frozenset(logging.makeLogRecord({}).__dict__)


class LogfmtFormatter(logging.Formatter):
    source = 'secure-boot-signer-digsigserver'

    def __init__(self) -> None:
        super().__init__()

    @staticmethod
    def _quote(text: str) -> str:
        if not text or any(ch.isspace() for ch in text) or any(ch in text for ch in '"='):
            text = (
                text.replace('\\', '\\\\')
                .replace('\n', '\\n')
                .replace('\r', '\\r')
                .replace('\t', '\\t')
                .replace('"', '\\"')
            )
            return f'"{text}"'
        return text

    @classmethod
    def _format_value(cls, value: object) -> str:
        if isinstance(value, bool):
            return 'true' if value else 'false'
        if value is None:
            return 'null'
        if isinstance(value, str):
            return cls._quote(value.strip())
        return cls._quote(str(value))

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created, UTC).strftime('%Y-%m-%dT%H:%M:%SZ')
        parts = [
            f'ts={timestamp}',
            f'level={record.levelname}',
            f'source={self._format_value(self.source)}',
            f'name={self._format_value(record.name)}',
        ]
        source_ip = getattr(record, 'source_ip', None)
        if source_ip:
            parts.append(f'source_ip={self._format_value(source_ip)}')
        ssl_client_s_dn = getattr(record, 'ssl_client_s_dn', None)
        if ssl_client_s_dn:
            parts.append(f'ssl_client_s_dn={self._format_value(ssl_client_s_dn)}')
        ssl_client_verify = getattr(record, 'ssl_client_verify', None)
        if ssl_client_verify:
            parts.append(f'ssl_client_verify={self._format_value(ssl_client_verify)}')

        extra_fields = {
            key: value
            for key, value in record.__dict__.items()
            if key not in STANDARD_LOG_RECORD_KEYS
            and key not in {'source_ip', 'ssl_client_s_dn', 'ssl_client_verify'}
        }

        if isinstance(record.msg, dict):
            for key, value in record.msg.items():
                parts.append(f'{key}={self._format_value(value)}')
        else:
            message = record.getMessage()
            if message:
                parts.append(f'msg={self._format_value(message)}')
        for key, value in extra_fields.items():
            parts.append(f'{key}={self._format_value(value)}')
        if record.exc_info:
            parts.append(f'exc_info={self._format_value(self.formatException(record.exc_info))}')
        return ' '.join(parts)


def setup_logfmt(
    logger_level: int | None = None,
    handler: logging.Handler | None = None,
    should_update_root_log_level: bool = True,
    should_include_thread_name: bool = False,
) -> None:
    del should_include_thread_name

    if logger_level is None:
        logger_level = logging.INFO

    root_logger = logging.getLogger()
    if should_update_root_log_level:
        root_logger.setLevel(logger_level)

    if handler is None:
        handler = logging.StreamHandler(stream=sys.stderr)

    handler.setLevel(logger_level)
    handler.setFormatter(LogfmtFormatter())
    root_logger.addHandler(handler)

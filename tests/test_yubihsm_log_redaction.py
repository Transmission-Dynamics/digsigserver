import logging
import subprocess

from digsigserver.logredaction import SecretRedactionFilter
from digsigserver.setup_logfmt import LogfmtFormatter
from digsigserver.utils import (
    _build_yubihsm_redaction_secrets,
    build_yubihsm_shell_command,
    get_digsigserver_yubihsm_connector,
    get_digsigserver_yubihsm_password_logs,
    get_hsm_audit_log_bucket,
    get_yubihsm_redaction_secrets,
    read_secret_file,
)


def _hash16(secret: str) -> str:
    return SecretRedactionFilter._redaction_token(secret)


def test_build_yubihsm_redaction_secrets_includes_split_fragments() -> None:
    assert _build_yubihsm_redaction_secrets('1234supersecret') == [
        '1234supersecret',
        'supersecret',
    ]


def test_redaction_filter_masks_split_yubihsm_password_fragments() -> None:
    redaction_filter = SecretRedactionFilter()
    redaction_filter.set_secrets(_build_yubihsm_redaction_secrets('1234supersecret'))

    record = logging.LogRecord(
        name='test',
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg='Command failed: %s',
        args=(['yubihsm-shell', '--authkey', '0x1234', '-p', 'supersecret'],),
        exc_info=None,
    )

    assert redaction_filter.filter(record) is True
    assert record.args == ()
    assert '0x1234' in record.msg
    assert 'supersecret' not in record.msg
    assert _hash16('supersecret') in record.msg


def test_redaction_filter_masks_called_process_error_command() -> None:
    redaction_filter = SecretRedactionFilter()
    redaction_filter.set_secrets(_build_yubihsm_redaction_secrets('0031password'))

    exc = subprocess.CalledProcessError(
        1,
        ['yubihsm-shell', '-a', 'get-logs', '--authkey', '0x0031', '-p', 'password'],
    )
    record = logging.LogRecord(
        name='test',
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg='audit log dump failed',
        args=(),
        exc_info=(type(exc), exc, None),
    )

    assert redaction_filter.filter(record) is True
    redacted_exc = record.exc_info[1]
    assert isinstance(redacted_exc, subprocess.CalledProcessError)
    assert redacted_exc.cmd == [
        'yubihsm-shell',
        '-a',
        'get-logs',
        '--authkey',
        '0x0031',
        '-p',
        _hash16('password'),
    ]


def test_redaction_filter_masks_final_formatted_string_and_extra_fields() -> None:
    redaction_filter = SecretRedactionFilter()
    redaction_filter.set_secrets(_build_yubihsm_redaction_secrets('0031password'))

    exc = subprocess.CalledProcessError(
        1,
        ['yubihsm-shell', '-a', 'get-logs', '--authkey', '0x0031', '-p', 'password'],
    )
    record = logging.LogRecord(
        name='test',
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg='audit command failed: %s',
        args=("Command '['yubihsm-shell', '--authkey', '0x0031', '-p', 'password']' returned status 1",),
        exc_info=(type(exc), exc, None),
    )
    record.audit_detail = "Command '['yubihsm-shell', '--authkey', '0x0031', '-p', 'password']' returned status 1"

    assert redaction_filter.filter(record) is True

    formatted = LogfmtFormatter().format(record)
    assert '0x0031' in formatted
    assert 'password' not in formatted
    assert _hash16('password') in formatted


def test_read_secret_file_strips_trailing_newline(tmp_path) -> None:
    secret_file = tmp_path / 'yubihsm-password'
    secret_file.write_text('0031supersecret\n', encoding='utf-8')

    assert read_secret_file(str(secret_file)) == '0031supersecret'


def test_get_hsm_audit_log_bucket_uses_env_override(monkeypatch) -> None:
    monkeypatch.setenv('HSM_AUDIT_LOG_BUCKET', 'td-yubihsm-backup-test')

    assert get_hsm_audit_log_bucket() == 'td-yubihsm-backup-test'


def test_get_hsm_audit_log_bucket_defaults_when_unset(monkeypatch) -> None:
    monkeypatch.delenv('HSM_AUDIT_LOG_BUCKET', raising=False)

    assert get_hsm_audit_log_bucket() == 'td-yubihsm-backup'


def test_get_digsigserver_yubihsm_password_logs_uses_logs_env_override(monkeypatch) -> None:
    monkeypatch.setenv('DIGSIGSERVER_YUBIHSM_PASSWORD', '0031signing-secret')
    monkeypatch.setenv('DIGSIGSERVER_YUBIHSM_PASSWORD_LOGS', '0022logs-secret')

    assert get_digsigserver_yubihsm_password_logs() == '0022logs-secret'


def test_get_digsigserver_yubihsm_password_logs_falls_back_to_signing_password(monkeypatch) -> None:
    monkeypatch.setenv('DIGSIGSERVER_YUBIHSM_PASSWORD', '0031signing-secret')
    monkeypatch.delenv('DIGSIGSERVER_YUBIHSM_PASSWORD_LOGS', raising=False)
    monkeypatch.delenv('DIGSIGSERVER_YUBIHSM_PASSWORD_LOGS_FILE', raising=False)

    assert get_digsigserver_yubihsm_password_logs() == '0031signing-secret'


def test_get_yubihsm_redaction_secrets_combines_signing_and_logs_passwords(monkeypatch) -> None:
    monkeypatch.setenv('DIGSIGSERVER_YUBIHSM_PASSWORD', '0031signing-secret')
    monkeypatch.setenv('DIGSIGSERVER_YUBIHSM_PASSWORD_LOGS', '0022logs-secret')

    assert get_yubihsm_redaction_secrets() == [
        '0031signing-secret',
        'signing-secret',
        '0022logs-secret',
        'logs-secret',
    ]


def test_get_digsigserver_yubihsm_connector_defaults_when_unset(monkeypatch) -> None:
    monkeypatch.delenv('DIGSIGSERVER_YUBIHSM_CONNECTOR', raising=False)

    assert get_digsigserver_yubihsm_connector() == 'http://host.docker.internal:12345'


def test_build_yubihsm_shell_command_includes_connector(monkeypatch) -> None:
    monkeypatch.setenv('DIGSIGSERVER_YUBIHSM_CONNECTOR', 'http://host.docker.internal:12345')

    assert build_yubihsm_shell_command('get-logs', '--out', 'audit.log') == [
        'yubihsm-shell',
        '--connector',
        'http://host.docker.internal:12345',
        '-a',
        'get-logs',
        '--out',
        'audit.log',
    ]
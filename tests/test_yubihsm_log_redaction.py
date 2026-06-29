import logging

from digsigserver.digsigserver.logredaction import SecretRedactionFilter
from digsigserver.digsigserver.utils import _build_yubihsm_redaction_secrets


def test_build_yubihsm_redaction_secrets_includes_split_fragments() -> None:
    assert _build_yubihsm_redaction_secrets('1234supersecret') == [
        '1234supersecret',
        '1234',
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
        args=(['yubihsm-shell', '--authkey', '1234', '-p', 'supersecret'],),
        exc_info=None,
    )

    assert redaction_filter.filter(record) is True
    assert record.args == (['yubihsm-shell', '--authkey', '<redacted>', '-p', '<redacted>'],)
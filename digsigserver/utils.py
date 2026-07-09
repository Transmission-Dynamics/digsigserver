from datetime import datetime
import os
import re
import shutil
import subprocess
from urllib.parse import urlparse
from sanic import request
from sanic.log import logger
from typing import Optional

from digsigserver.logredaction import install_log_redaction_filter


def extract_files(workdir: str, f: request.File) -> bool:
    try:
        subprocess.run(['tar', '-x', '-z', '-f-'],
                       input=f.body, check=True,
                       cwd=workdir)
    except subprocess.CalledProcessError as e:
        logger.warning("tar failure: {}\n".format(e.stderr))
        return False
    return True


def repack_files(workdir: str, outfile: str, file_list: Optional[list] = None) -> bool:
    if file_list is None:
        file_list = ['.']
    try:
        subprocess.run(['tar', '-c', '-z', '-v', '-f', outfile] + file_list,
                       stdin=subprocess.DEVNULL, check=True,
                       capture_output=True, cwd=workdir)
    except subprocess.CalledProcessError as e:
        logger.warning("tar failure on repack: {}\n".format(e.stderr))
        return False
    return True


def uri_exists(uri: str, is_dir=False) -> bool:
    u = urlparse(uri)
    if u.scheme == 'file' or u.scheme == '':
        return os.path.isdir(u.path) if is_dir else os.path.exists(u.path)
    if u.scheme == 's3':
        if is_dir and not uri.endswith('/'):
            uri += '/'
        cmd = ['aws', 's3', 'ls', uri]
        try:
            subprocess.run(cmd, check=True, encoding='utf-8',
                           stdin=subprocess.DEVNULL, capture_output=True)
            return True
        except subprocess.CalledProcessError as e:
            logger.warning('cmd: {}\nstderr: {}'.format(' '.join(cmd), e.stderr))
            return False
    logger.error('unrecognized URI: {}'.format(uri))
    return False


def uri_fetch(uri: str, dest: str, is_dir=False):
    u = urlparse(uri)
    if u.scheme == 'file' or u.scheme == '':
        if is_dir:
            for f in os.listdir(u.path):
                shutil.copyfile(os.path.join(u.path, f), os.path.join(dest, f))
        else:
            shutil.copyfile(u.path, dest)
        return
    if u.scheme == 's3':
        cmd = ['aws', 's3', 'cp', uri, dest]
        if is_dir:
            cmd.append('--recursive')
        try:
            proc = subprocess.run(cmd,
                                  check=True, encoding='utf-8',
                                  stdin=subprocess.DEVNULL, capture_output=True)
            logger.debug("cmd: {}\noutput: {}\n".format(' '.join(cmd), proc.stdout))
        except subprocess.CalledProcessError as e:
            raise RuntimeError('cmd: {}\nstderr: {}'.format(' '.join(cmd), e.stderr))
        return
    raise RuntimeError('unrecognized URI: {}'.format(uri))


def upload_file(filename: str, uri: str):
    u = urlparse(uri)
    if u.scheme == 'file' or u.scheme == '':
        shutil.copyfile(filename, u.path)
        return
    if u.scheme == 's3':
        cmd = ['aws', 's3', 'cp', filename, uri]
        logger.info("Running: {}".format(cmd))
        try:
            subprocess.run(cmd,
                           check=True, encoding='utf-8',
                           stdin=subprocess.DEVNULL, capture_output=True)
        except subprocess.CalledProcessError as e:
            raise RuntimeError('cmd:{}\nstderr: {}'.format(' '.join(cmd), e.stderr))
        return
    raise RuntimeError('unrecognized URI: {}'.format(uri))


def to_boolean(boolstr: Optional[str]) -> bool:
    if not boolstr:
        return False
    return boolstr.upper() in ["Y", "YES", "1", "T", "TRUE", "ON"]


def _extract_last_log_item_index(log_content: str) -> Optional[int]:
    for line in reversed(log_content.splitlines()):
        match = re.match(r'\s*item:\s*(\d+)\s+--', line)
        if match:
            return int(match.group(1))
    return None


def _build_yubihsm_redaction_secrets(password: str) -> list[str]:
    pass_value = password[4:]
    return [password, pass_value]


def _split_yubihsm_password(password: str) -> tuple[str, str]:
    return f"0x{password[0:4]}", password[4:]


def read_secret_file(path: Optional[str]) -> Optional[str]:
    if not path:
        return None

    try:
        with open(path, 'r', encoding='utf-8') as secret_file:
            secret_value = secret_file.read().strip()
    except OSError:
        logger.warning('Unable to read secret file: %s', path)
        return None

    return secret_value or None


def get_digsigserver_yubihsm_password() -> Optional[str]:
    password = read_secret_file(os.environ.get('DIGSIGSERVER_YUBIHSM_PASSWORD_FILE'))
    if password is not None:
        return password
    return os.environ.get('DIGSIGSERVER_YUBIHSM_PASSWORD')


def get_digsigserver_yubihsm_password_logs() -> Optional[str]:
    password = read_secret_file(os.environ.get('DIGSIGSERVER_YUBIHSM_PASSWORD_LOGS_FILE'))
    if password is not None:
        return password

    password = os.environ.get('DIGSIGSERVER_YUBIHSM_PASSWORD_LOGS')
    if password is not None:
        return password

    return get_digsigserver_yubihsm_password()


def get_yubihsm_redaction_secrets() -> list[str]:
    secrets: list[str] = []

    for password in (get_digsigserver_yubihsm_password(), get_digsigserver_yubihsm_password_logs()):
        if password and len(password) > 4:
            for secret in _build_yubihsm_redaction_secrets(password):
                if secret not in secrets:
                    secrets.append(secret)

    return secrets


def get_hsm_audit_log_target() -> str:
    target = os.environ.get('HSM_AUDIT_LOG_TARGET', 'hsm-main')
    if target in {'hsm-main', 'hsm-backup'}:
        return target

    logger.warning('Invalid HSM_AUDIT_LOG_TARGET=%s, defaulting to hsm-main', target)
    return 'hsm-main'


def get_hsm_audit_log_bucket() -> str:
    bucket = os.environ.get('HSM_AUDIT_LOG_BUCKET', 'td-yubihsm-backup').strip()
    if bucket:
        return bucket

    logger.warning('Invalid HSM_AUDIT_LOG_BUCKET=%s, defaulting to td-yubihsm-backup', bucket)
    return 'td-yubihsm-backup'


def get_digsigserver_yubihsm_connector() -> str:
    connector = os.environ.get('DIGSIGSERVER_YUBIHSM_CONNECTOR', 'http://host.docker.internal:12345').strip()
    if connector:
        return connector

    logger.warning(
        'Invalid DIGSIGSERVER_YUBIHSM_CONNECTOR=%s, defaulting to http://host.docker.internal:12345',
        connector,
    )
    return 'http://host.docker.internal:12345'


def build_yubihsm_shell_command(action: str, *args: str) -> list[str]:
    return [
        'yubihsm-shell',
        '--connector',
        get_digsigserver_yubihsm_connector(),
        '-a',
        action,
        *args,
    ]


async def dump_upload_and_reset_logs() -> None:
    from digsigserver.server import LogAuditCategory, log_audit

    password = get_digsigserver_yubihsm_password_logs()
    if not password or len(password) <= 4:
        logger.warning('Skipping YubiHSM audit log dump: YubiHSM password is not configured correctly')
        return

    auth_key, pass_value = _split_yubihsm_password(password)

    timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    temp_log_file = f'audit-{timestamp_str}.log'
    upload_uri = f's3://{get_hsm_audit_log_bucket()}/logs/{get_hsm_audit_log_target()}/{temp_log_file}'
    upload_succeeded = False

    try:
        subprocess.run(
            build_yubihsm_shell_command('get-logs', '--out', temp_log_file, '--authkey', auth_key, '-p', pass_value),
            check=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            encoding='utf-8',
        )

        with open(temp_log_file, 'r', encoding='utf-8') as f:
            log_content = f.read()

        last_item_index = _extract_last_log_item_index(log_content)
        if last_item_index is None:
            logger.warning('Skipping YubiHSM audit log index update: no log items found in %s', temp_log_file)
            return

        upload_file(temp_log_file, upload_uri)
        upload_succeeded = True

        set_log_index = last_item_index - 1
        if upload_succeeded:
            subprocess.run(
                build_yubihsm_shell_command(
                    'set-log-index',
                    '--log-index',
                    str(set_log_index),
                    '--authkey',
                    auth_key,
                    '-p',
                    pass_value,
                ),
                check=True,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                encoding='utf-8',
            )

        log_audit(
            LogAuditCategory.AUDIT_LOG_EVENTS,
            'yubihsm_audit_logs_archived',
            'success',
            upload_uri=upload_uri,
            upload_succeeded=upload_succeeded,
            log_item_index=last_item_index,
            set_log_index=set_log_index,
            log_line_count=len(log_content.splitlines()),
        )
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        logger.exception('Failed to dump and archive YubiHSM audit logs')
        log_audit(
            LogAuditCategory.AUDIT_LOG_EVENTS,
            'yubihsm_audit_logs_archived',
            'failure',
            level=40,
            exc=exc,
            upload_uri=upload_uri,
        )
    finally:
        if os.path.exists(temp_log_file):
            os.remove(temp_log_file)
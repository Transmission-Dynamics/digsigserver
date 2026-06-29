from datetime import datetime
import os
import random
import re
import shutil
import subprocess
from urllib.parse import urlparse
import uuid
from astral import now
from sanic import request
from sanic.log import logger
from typing import Optional

from digsigserver.digsigserver.logredaction import install_log_redaction_filter
from digsigserver.digsigserver.server import LogAuditCategory, log_audit


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
    auth_key = password[0:4]
    pass_value = password[4:]
    return [password, auth_key, pass_value]


async def dump_upload_and_reset_logs() -> None:
    password = os.environ.get('DIGSIGSERVER_YUBIHSM_PASSWORD')
    if not password or len(password) <= 4:
        logger.warning('Skipping YubiHSM audit log dump: DIGSIGSERVER_YUBIHSM_PASSWORD is not configured correctly')
        return

    auth_key, pass_value = _build_yubihsm_redaction_secrets(password)[1:]
    install_log_redaction_filter(_build_yubihsm_redaction_secrets(password))

    timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    temp_log_file = f'audit-{timestamp_str}.log'
    upload_uri = f's3://td-yubihsm-backup/logs/hsm-main/{temp_log_file}'
    upload_succeeded = False

    try:
        subprocess.run(
            ['yubihsm-shell', '-a', 'get-logs', '--out', temp_log_file, '--authkey', auth_key, '-p', pass_value],
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
                ['yubihsm-shell', '-a', 'set-log-index', '--log-index', str(set_log_index), '--authkey', auth_key, '-p', pass_value],
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
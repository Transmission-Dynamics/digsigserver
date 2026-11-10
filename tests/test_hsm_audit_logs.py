import asyncio
from pathlib import Path
import subprocess
import threading
from unittest.mock import Mock

import pytest

from digsigserver import server, utils


@pytest.fixture
def archive(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(utils, 'get_digsigserver_yubihsm_password_logs', lambda: '0022test-secret')
    monkeypatch.setenv('HSM_AUDIT_LOG_BUCKET', 'test-audit-bucket')
    monkeypatch.setenv('HSM_AUDIT_LOG_TARGET', 'hsm-backup')
    events = []

    def run(cmd, **kwargs):
        action = cmd[cmd.index('-a') + 1]
        events.append(action)
        if action == 'get-logs':
            Path(cmd[cmd.index('--out') + 1]).write_text('Found 62 items\nitem: 1567 -- cmd: 0x04\nitem: 1628 -- cmd: 0x55\n')
        assert kwargs['timeout'] == 30
        return subprocess.CompletedProcess(cmd, 0, stdout='Log used:\t\t62/62\n')

    def upload(filename, uri, **kwargs):
        assert Path(filename).read_text().endswith('item: 1628 -- cmd: 0x55\n')
        assert uri.startswith('s3://test-audit-bucket/logs/hsm-backup/audit-')
        assert kwargs['timeout'] == 120
        events.append('upload')

    command = Mock(side_effect=run)
    monkeypatch.setattr(utils.subprocess, 'run', command)
    monkeypatch.setattr(utils, 'upload_file', upload)
    monkeypatch.setattr(server, 'log_audit', Mock())
    return events, command, tmp_path


def test_archives_full_log_before_reset(archive):
    events, command, tmp_path = archive
    utils.dump_upload_and_reset_logs()
    assert events == ['get-logs', 'upload', 'set-log-index']
    reset = command.call_args.args[0]
    assert reset[reset.index('--log-index') + 1] == '1627'
    assert not list(tmp_path.glob('audit-*.log'))
    assert server.log_audit.call_args.args[2] == 'success'


@pytest.mark.parametrize('error', [RuntimeError('S3 unavailable'), subprocess.TimeoutExpired('aws', 120)])
def test_failed_upload_never_resets_and_next_run_retries(archive, monkeypatch, error):
    events, _, _ = archive
    upload = utils.upload_file
    monkeypatch.setattr(utils, 'upload_file', Mock(side_effect=error))
    utils.dump_upload_and_reset_logs()
    assert events == ['get-logs']
    assert server.log_audit.call_args.args[2] == 'failure'
    monkeypatch.setattr(utils, 'upload_file', upload)
    utils.dump_upload_and_reset_logs()
    assert events == ['get-logs', 'get-logs', 'upload', 'set-log-index']


def test_failed_reset_is_reported(archive):
    events, command, _ = archive
    run = command.side_effect

    def fail_reset(cmd, **kwargs):
        run(cmd, **kwargs)
        if 'set-log-index' in cmd:
            raise subprocess.CalledProcessError(1, cmd, stderr='Permission denied')

    command.side_effect = fail_reset
    utils.dump_upload_and_reset_logs()
    assert events == ['get-logs', 'upload', 'set-log-index']
    assert server.log_audit.call_args.kwargs['stderr'] == 'Permission denied'
    assert server.log_audit.call_args.args[2] == 'failure'


def test_empty_dump_is_not_uploaded_or_reset(archive):
    events, command, _ = archive

    def empty_dump(cmd, **kwargs):
        events.append('get-logs')
        Path(cmd[cmd.index('--out') + 1]).write_text('Found 0 items\n')

    command.side_effect = empty_dump
    utils.dump_upload_and_reset_logs()
    assert events == ['get-logs']


def test_index_wraparound(archive, monkeypatch):
    _, command, _ = archive
    monkeypatch.setattr(utils, '_extract_last_log_item_index', lambda _: 0)
    utils.dump_upload_and_reset_logs()
    reset = command.call_args.args[0]
    assert reset[reset.index('--log-index') + 1] == '65535'


def test_collector_runs_immediately_and_repeats_without_requests(monkeypatch):
    calls = []
    main_thread = threading.get_ident()
    def collect(**kwargs):
        assert kwargs == {'only_if_needed': True}
        calls.append(threading.get_ident())

    monkeypatch.setattr(utils, 'dump_upload_and_reset_logs', collect)

    async def sleep(delay):
        assert delay == 30
        if len(calls) == 2:
            raise asyncio.CancelledError

    monkeypatch.setattr(server.asyncio, 'sleep', sleep)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(server.monitor_hsm_audit_logs(None))
    assert len(calls) == 2
    assert all(thread != main_thread for thread in calls)


def test_app_registers_collector(monkeypatch):
    add_task = Mock()
    monkeypatch.setattr(server.Sanic, 'add_task', add_task)
    app = server.create_app()
    try:
        add_task.assert_called_once_with(server.monitor_hsm_audit_logs)
    finally:
        server.Sanic.unregister_app(app)


@pytest.mark.parametrize('used', [0, 3, 30])
def test_idle_monitor_never_logs_in_or_uploads(archive, used):
    events, command, tmp_path = archive
    command.return_value = subprocess.CompletedProcess([], 0, stdout=f'Log used:\t\t{used}/62\n')
    command.side_effect = None
    utils.dump_upload_and_reset_logs(only_if_needed=True)
    command.assert_called_once()
    assert command.call_args.args[0][-2:] == ['-a', 'get-device-info']
    assert events == []
    assert not list(tmp_path.glob('audit-*.log'))


@pytest.mark.parametrize('used', [31, 61, 62])
def test_monitor_archives_at_half_capacity_or_above(archive, used):
    events, command, _ = archive
    run = command.side_effect

    def device_info(cmd, **kwargs):
        result = run(cmd, **kwargs)
        result.stdout = f'Log used:\t\t{used}/62\n'
        return result

    command.side_effect = device_info
    utils.dump_upload_and_reset_logs(only_if_needed=True)
    assert events == ['get-device-info', 'get-logs', 'upload', 'set-log-index']


@pytest.mark.parametrize('output', ['unexpected output', 'Log used: 0/0', 'Log used: 63/62'])
def test_invalid_usage_reports_failure_without_reset(archive, output):
    events, command, _ = archive
    command.side_effect = None
    command.return_value = subprocess.CompletedProcess([], 0, stdout=output)
    utils.dump_upload_and_reset_logs(only_if_needed=True)
    command.assert_called_once()
    assert events == []
    assert server.log_audit.call_args.args[2] == 'failure'


def test_request_and_monitor_archives_do_not_overlap(monkeypatch):
    started = threading.Event()
    release = threading.Event()
    calls = []

    def collect(**kwargs):
        calls.append(kwargs)
        started.set()
        assert release.wait(timeout=5)

    monkeypatch.setattr(utils, '_dump_upload_and_reset_logs', collect)

    async def run():
        first = asyncio.create_task(asyncio.to_thread(utils.dump_upload_and_reset_logs))
        try:
            assert await asyncio.to_thread(started.wait, 5)
            second = asyncio.create_task(asyncio.to_thread(utils.dump_upload_and_reset_logs, only_if_needed=True))
            await asyncio.sleep(0)
            assert len(calls) == 1
        finally:
            release.set()
        await asyncio.gather(first, second)

    asyncio.run(run())
    assert calls == [{'only_if_needed': False}, {'only_if_needed': True}]

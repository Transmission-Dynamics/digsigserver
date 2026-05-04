import asyncio
import logging
import tempfile
from typing import Optional
import re
import os
import uuid
import ipaddress
from contextvars import ContextVar

from sanic import Sanic, request
from sanic.exceptions import SanicException
from sanic.log import logger
from sanic.response import text

from digsigserver.signers.tegrasign import TegraSigner
from digsigserver.signers.imxsign import IMXSigner
from digsigserver.signers.kmodsign import KernelModuleSigner
from digsigserver.signers.opteesign import OPTEESigner
from digsigserver.signers.mendersign import MenderSigner
from digsigserver.signers.swupdsign import SwupdateSigner
from digsigserver.signers.rksign import RockchipSigner
from digsigserver.signers.rkopteesign import RockchipOpteeSigner
from digsigserver.signers.uefisign import UefiSigner
from digsigserver.signers.ueficapsulesign import UefiCapsuleSigner
from digsigserver.signers.ekbsign import EKBSigner
from digsigserver.signers.fitimagesign import FitImageSigner
from digsigserver.logredaction import install_log_redaction_filter
from . import utils

# Signing can take a loooong time, so set a more reasonable
# default response timeout
CodesignSanicDefaults = {
    'RESPONSE_TIMEOUT': 600,
    'REQUEST_MAX_SIZE': 600000000,
    'L4T_TOOLS_BASE': '/opt/nvidia',
    'IMX_CST_BASE': '/opt/NXP',
    'KEYFILE_URI': 'file:///please/configure/this/path',
    'LOG_LEVEL': 'DEBUG',
    'SOURCE_IP_WHITELIST': '',
}

"""
Actual initialization happens here
"""


request_source_ip: ContextVar[str | None] = ContextVar('request_source_ip', default=None)
request_ssl_client_s_dn: ContextVar[str | None] = ContextVar('request_ssl_client_s_dn', default=None)
request_ssl_client_verify: ContextVar[str | None] = ContextVar('request_ssl_client_verify', default=None)
TRUSTED_PROXY_IPS = {'172.30.0.11'}


def load_dotenv(path: str = '.env') -> None:
    if not os.path.exists(path):
        return
    with open(path, mode='r', encoding='utf-8') as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('export '):
                line = line[7:].lstrip()
            key, sep, value = line.partition('=')
            if not sep:
                continue
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            os.environ.setdefault(key, value)


def create_app() -> Sanic:
    load_dotenv(os.environ.get('DIGSIGSERVER_DOTENV', '.env'))
    resolved_level = resolve_log_level(os.environ.get('DIGSIGSERVER_LOG_LEVEL', CodesignSanicDefaults['LOG_LEVEL']))
    app = Sanic(name='digsigserver', env_prefix='DIGSIGSERVER_', log_config=build_sanic_log_config(resolved_level))
    app.config.update_config(CodesignSanicDefaults)
    app.config.load_environment_vars(prefix='DIGSIGSERVER_')
    install_log_redaction_filter([app.config.get('YUBIHSM_PASSWORD')])
    install_request_logging_filter()
    attach_request_context_handlers(app)
    attach_exception_handlers(app)
    attach_endpoints(app)
    return app


def resolve_log_level(log_level: int | str | None) -> int:
    if isinstance(log_level, int):
        return log_level
    if isinstance(log_level, str):
        resolved_level = logging.getLevelNamesMapping().get(log_level.upper())
        if resolved_level is not None:
            return resolved_level
        raise ValueError(f'Invalid LOG_LEVEL: {log_level}')
    return logging.INFO


def build_sanic_log_config(log_level: int) -> dict:
    return {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'logfmt': {
                '()': 'digsigserver.setup_logfmt.LogfmtFormatter',
            },
        },
        'handlers': {
            'stderr': {
                'class': 'logging.StreamHandler',
                'formatter': 'logfmt',
                'level': log_level,
                'stream': 'ext://sys.stderr',
            },
            'stdout': {
                'class': 'logging.StreamHandler',
                'formatter': 'logfmt',
                'level': log_level,
                'stream': 'ext://sys.stdout',
            },
        },
        'loggers': {
            'sanic.root': {'handlers': ['stderr'], 'level': log_level, 'propagate': False},
            'sanic.error': {'handlers': ['stderr'], 'level': log_level, 'propagate': False},
            'sanic.server': {'handlers': ['stderr'], 'level': log_level, 'propagate': False},
            'sanic.websockets': {'handlers': ['stderr'], 'level': log_level, 'propagate': False},
            'sanic.access': {'handlers': ['stdout'], 'level': log_level, 'propagate': False},
        },
        'root': {
            'handlers': ['stderr'],
            'level': log_level,
        },
    }


class RequestContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        source_ip = request_source_ip.get()
        if source_ip:
            record.source_ip = source_ip
        ssl_client_s_dn = request_ssl_client_s_dn.get()
        if ssl_client_s_dn:
            record.ssl_client_s_dn = ssl_client_s_dn
        ssl_client_verify = request_ssl_client_verify.get()
        if ssl_client_verify:
            record.ssl_client_verify = ssl_client_verify
        return True


def install_request_logging_filter() -> None:
    request_filter = RequestContextFilter()
    for logger_name in ('', 'sanic.root', 'sanic.error', 'sanic.server', 'sanic.websockets', 'sanic.access'):
        target_logger = logging.getLogger(logger_name)
        if any(isinstance(existing_filter, RequestContextFilter) for existing_filter in target_logger.filters):
            continue
        target_logger.addFilter(request_filter)


class LogAuditCategory:
    ACCESS_CONTROL = 'accessControl'
    REQUEST_ERRORS = 'requestErrors'
    CONTROL_SYSTEM_EVENTS = 'controlSystemEvents'
    BACKUP_AND_RESTORE_EVENTS = 'backupAndRestoreEvents'
    CONFIGURATION_CHANGES = 'configurationChanges'
    AUDIT_LOG_EVENTS = 'auditLogEvents'
    PKI_SIGNING = 'pkiSigning'


def build_audit_payload(category: str, event_type: str, event_result: object, **fields) -> dict:
    payload = {
        'audit': True,
        'category': category,
        'type': event_type,
        'event_id': str(uuid.uuid4()),
        'event_result': event_result,
    }
    for key, value in fields.items():
        if value is not None:
            payload[key] = value
    return payload


def log_audit(
    category: str,
    event_type: str,
    event_result: object,
    *,
    level: int = logging.INFO,
    exc: Exception | None = None,
    **fields,
) -> None:
    payload = build_audit_payload(category, event_type, event_result, **fields)
    logger.log(level, payload, exc_info=exc)


def log_signing_audit(event_type: str, event_result: str, **fields) -> None:
    log_audit(LogAuditCategory.PKI_SIGNING, event_type, event_result, **fields)


def parse_csv_config(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in str(value).split(',') if item.strip()]


def get_peer_ip(req: request) -> str | None:
    remote_addr = getattr(req, 'remote_addr', None)
    if isinstance(remote_addr, tuple):
        return remote_addr[0]
    return remote_addr


def get_source_ip(req: request) -> str | None:
    peer_ip = get_peer_ip(req)
    if peer_ip not in TRUSTED_PROXY_IPS:
        return peer_ip

    forwarded_for = req.headers.get('x-forwarded-for')
    if not forwarded_for:
        return peer_ip

    forwarded_ips = parse_csv_config(forwarded_for)
    return forwarded_ips[0] if forwarded_ips else peer_ip


def is_ip_allowed(req: request, source_ip: str | None) -> bool:
    whitelist = parse_csv_config(req.app.config.get('SOURCE_IP_WHITELIST'))
    if not whitelist or not source_ip:
        return True

    source_address = ipaddress.ip_address(source_ip)
    for entry in whitelist:
        try:
            if '/' in entry:
                if source_address in ipaddress.ip_network(entry, strict=False):
                    return True
            elif source_address == ipaddress.ip_address(entry):
                return True
        except ValueError:
            logger.warning('Invalid SOURCE_IP_WHITELIST entry: %s', entry)
    return False


def attach_request_context_handlers(app: Sanic):
    @app.on_request
    async def bind_request_source_ip(req: request):
        source_ip = get_source_ip(req)
        ssl_client_s_dn = req.headers.get('x-ssl-client-s-dn')
        ssl_client_verify = req.headers.get('x-ssl-client-verify')
        req.ctx.source_ip = source_ip
        req.ctx.ssl_client_s_dn = ssl_client_s_dn
        req.ctx.ssl_client_verify = ssl_client_verify
        request_source_ip.set(source_ip)
        request_ssl_client_s_dn.set(ssl_client_s_dn)
        request_ssl_client_verify.set(ssl_client_verify)
        if not is_ip_allowed(req, source_ip):
            log_audit(LogAuditCategory.ACCESS_CONTROL, 'source_ip_denied', 'failure',
                      source_ip=source_ip, request_path=req.path, request_method=req.method)
            return text('Forbidden', status=403)

    @app.on_response
    async def clear_request_source_ip(req: request, res):
        del res
        del req
        request_source_ip.set(None)
        request_ssl_client_s_dn.set(None)
        request_ssl_client_verify.set(None)


def attach_exception_handlers(app: Sanic):
    @app.exception(SanicException)
    async def handle_sanic_exception(req: request, exc: SanicException):
        log_audit(
            LogAuditCategory.REQUEST_ERRORS,
            'http_exception',
            'failure',
            level=logging.ERROR,
            exc=exc,
            request_path=req.path,
            request_method=req.method,
            source_ip=getattr(req.ctx, 'source_ip', None),
            ssl_client_s_dn=getattr(req.ctx, 'ssl_client_s_dn', None),
            ssl_client_verify=getattr(req.ctx, 'ssl_client_verify', None),
            status_code=getattr(exc, 'status_code', 500),
        )
        return text(str(exc), status=getattr(exc, 'status_code', 500))

    @app.exception(Exception)
    async def handle_unexpected_error(req: request, exc: Exception):
        log_audit(
            LogAuditCategory.REQUEST_ERRORS,
            'unhandled_exception',
            'failure',
            level=logging.ERROR,
            exc=exc,
            request_path=req.path,
            request_method=req.method,
            source_ip=getattr(req.ctx, 'source_ip', None),
            ssl_client_s_dn=getattr(req.ctx, 'ssl_client_s_dn', None),
            ssl_client_verify=getattr(req.ctx, 'ssl_client_verify', None),
        )
        return text('Signing error', status=500)


def config_get(item: str, default_value=None) -> str:
    return Sanic.get_app('digsigserver').config.get(item, default_value)


def validate_upload(req: request, name: str, ok_types: Optional[list] = None) -> request.File:
    if not ok_types:
        ok_types = ["application/octet-stream"]
    f = req.files.get(name)
    return f if f and f.type in ok_types else None


def parse_manifest(manifest_file: str) -> dict:
    result = {}
    if not os.path.exists(manifest_file):
        return result
    with open(manifest_file, mode='r', encoding='utf-8') as f:
        for line in f:
            logger.info("manifest line: {}".format(line.rstrip()))
            m = re.match(r'([^=]+)=(.*)', line.rstrip())
            if m is None:
                raise ValueError('invalid syntax in manifest file')
            result[m.group(1)] = m.group(2)
    return result


async def return_file(req: request, filename: str, return_filename: str):
    response = await req.respond(content_type="application/octet-stream",
                                 headers={"Content-Disposition": f'Attachment; filename="{return_filename}"'})
    with open(filename, "rb") as f:
        while True:
            data = f.read(8192)
            if not data:
                break
            await response.send(data, False)
    await response.eof()


async def return_tarball(req: request, workdir: str, return_filename: str = "signed-artifact.tar.gz",
                         files_to_return: Optional[list] = None):
    outfile = tempfile.NamedTemporaryFile(delete=False)
    outfile.close()
    if utils.repack_files(workdir, outfile.name, file_list=files_to_return):
        await return_file(req, outfile.name, return_filename)
        response = None
    else:
        response = text("Signing error", status=500)
    os.unlink(outfile.name)
    return response


def attach_endpoints(app: Sanic):
    @app.get("/health")
    async def health_handler(req: request):
        return text("OK")

    @app.post("/sign/tegra")
    async def sign_handler_tegra(req: request):
        f = validate_upload(req, "artifact")
        if not f:
            return text("Invalid artifact", status=400)
        with tempfile.TemporaryDirectory() as workdir:
            try:
                s = TegraSigner(app, workdir, req.form.get("machine"), req.form.get("soctype"),
                                req.form.get("bspversion"))
            except ValueError:
                return text("Invalid parameters", status=400)

            if await asyncio.get_running_loop().run_in_executor(None, utils.extract_files, workdir, f):
                try:
                    envvars = parse_manifest(os.path.join(workdir, 'MANIFEST'))
                except ValueError:
                    return text("Invalid manifest", status=400)
                if 'BUPGENSPECS' in envvars:
                    result = await asyncio.get_running_loop().run_in_executor(None, s.multisign, envvars)
                elif 'SIGNFILES' in envvars:
                    result = await asyncio.get_running_loop().run_in_executor(None, s.signfiles, envvars)
                else:
                    result = await asyncio.get_running_loop().run_in_executor(None, s.sign, envvars)
                if result:
                    log_signing_audit('tegra_sign', 'success', machine=req.form.get('machine'),
                                      soctype=req.form.get('soctype'), bsp_version=req.form.get('bspversion'))
                    return await return_tarball(req, workdir)
        log_signing_audit('tegra_sign', 'failure', machine=req.form.get('machine'),
                          soctype=req.form.get('soctype'), bsp_version=req.form.get('bspversion'))
        return text("Signing error", status=500)

    @app.post("/sign/rk")
    async def sign_handler_rk_kernel_fit(req: request):
        f = validate_upload(req, "artifact")
        if not f:
            return text("Invalid artifact", status=400)
        with tempfile.TemporaryDirectory() as workdir:
            try:
                s = RockchipSigner(app, workdir, req.form.get("machine"), req.form.get("soctype"))
            except ValueError:
                return text("Invalid parameters", status=400)

            artifact_type = req.form.get("artifact_type").lower()
            burn_key_hash = utils.to_boolean(req.form.get("burn_key_hash", "no"))
            if artifact_type not in ["fit-image", "idblock", "usbloader"]:
                return text("Invalid artifact type", status=400)
            if artifact_type == "fit-image":
                external_data_offset = req.form.get("external_data_offset", "")
                if await asyncio.get_running_loop().run_in_executor(None, utils.extract_files,
                                                                    workdir, f):
                    if await asyncio.get_running_loop().run_in_executor(None, s.sign, artifact_type,
                                                                        burn_key_hash, None, None, external_data_offset):
                        log_signing_audit('rockchip_sign', 'success', artifact_type=artifact_type,
                                          machine=req.form.get('machine'), soctype=req.form.get('soctype'))
                        await return_tarball(req, workdir, s.fit_image_output_files)
                        response = None
                    else:
                        log_signing_audit('rockchip_sign', 'failure', artifact_type=artifact_type,
                                          machine=req.form.get('machine'), soctype=req.form.get('soctype'))
                        response = text("Signing error", status=500)
            else:
                with open(os.path.join(workdir, "artifact"), "wb") as artifact:
                    artifact.write(f.body)
                outfile = tempfile.NamedTemporaryFile(delete=False)
                outfile.close()
                if await asyncio.get_running_loop().run_in_executor(None, s.sign, artifact_type,
                                                                burn_key_hash, artifact.name, outfile.name, None):
                    log_signing_audit('rockchip_sign', 'success', artifact_type=artifact_type,
                                      machine=req.form.get('machine'), soctype=req.form.get('soctype'))
                    await return_file(req, outfile.name, "artifact.signed")
                    response = None
                else:
                    log_signing_audit('rockchip_sign', 'failure', artifact_type=artifact_type,
                                      machine=req.form.get('machine'), soctype=req.form.get('soctype'))
                    response = text("Signing error", status=500)
        return response

    @app.post("/sign/imx")
    async def sign_handler_imx(req: request):
        csf = validate_upload(req, "csf", ok_types=["text/plain"])
        if not csf:
            return text("Invalid CSF", status=400)
        f = validate_upload(req, "artifact")
        if not f:
            return text("Invalid artifact", status=400)
        with tempfile.TemporaryDirectory() as workdir:
            try:
                s = IMXSigner(app, workdir, req.form.get("machine"), req.form.get("soctype"),
                              req.form.get("cstversion"), req.form.get("backend"))
            except ValueError:
                return text("Invalid parameters", status=400)

            with open(os.path.join(workdir, "csf-input.txt"), "w") as csfinput:
                csfinput.write(csf.body.decode('UTF-8'))
            with open(os.path.join(workdir, f.name), "wb") as artifact:
                artifact.write(f.body)

            outfile = tempfile.NamedTemporaryFile(delete=False)
            outfile.close()

            if await asyncio.get_running_loop().run_in_executor(None, s.sign, outfile.name):
                log_signing_audit('imx_sign', 'success', machine=req.form.get('machine'),
                                  soctype=req.form.get('soctype'), cst_version=req.form.get('cstversion'),
                                  backend=req.form.get('backend'))
                await return_file(req, outfile.name, "artifact.signed")
                response = None
            else:
                log_signing_audit('imx_sign', 'failure', machine=req.form.get('machine'),
                                  soctype=req.form.get('soctype'), cst_version=req.form.get('cstversion'),
                                  backend=req.form.get('backend'))
                response = text("Signing error", status=500)
        return response

    @app.post("/sign/fitimage")
    async def sign_handler_fitimage(req: request):
        f = validate_upload(req, "artifact")
        if not f:
            return text("Invalid artifact", status=400)
        backend = req.form.get("backend")
        keyname = req.form.get("keyname")
        if backend == "pkcs11" and not keyname:
            return text("Key URI missing for PKCS#11 backend", status=400)
        if not keyname:
            keyname = "dev"
        with tempfile.TemporaryDirectory() as workdir:
            try:
                s = FitImageSigner(app, workdir, backend)
            except ValueError:
                return text("Invalid parameters", status=400)

            with open(os.path.join(workdir, "artifact"), "wb") as artifact:
                artifact.write(f.body)

            outfile = tempfile.NamedTemporaryFile(delete=False)
            outfile.close()
            if await asyncio.get_running_loop().run_in_executor(None, s.sign,
                                   artifact.name,
                                   None,
                                   req.form.get("external_data_offset"),
                                   req.form.get("mark_required"),
                                    req.form.get("algo"),
                                   keyname,
                                   req.form.get("comment")):
                log_signing_audit('fitimage_sign', 'success', backend=backend,
                                  mark_required=bool(req.form.get('mark_required')),
                                  algo=req.form.get('algo'),
                                  has_comment=bool(req.form.get('comment')))
                await return_file(req, artifact.name, "artifact.signed")
                response = None
            else:
                log_signing_audit('fitimage_sign', 'failure', backend=backend,
                                  mark_required=bool(req.form.get('mark_required')),
                                  algo=req.form.get('algo'),
                                  has_comment=bool(req.form.get('comment')))
                response = text("Signing error", status=500)
        return response

    @app.post("/sign/modules")
    async def sign_handler_modules(req: request):
        f = validate_upload(req, "artifact")
        if not f:
            return text("Invalid artifact", status=400)
        with tempfile.TemporaryDirectory() as workdir:
            try:
                s = KernelModuleSigner(app, workdir, req.form.get("machine"), req.form.get("hashalg", "sha512"))
            except ValueError:
                return text("Invalid parameters", status=400)

            if await asyncio.get_running_loop().run_in_executor(None, utils.extract_files, workdir, f):
                result = await asyncio.get_running_loop().run_in_executor(None, s.sign)
                if result:
                    log_signing_audit('module_sign', 'success', machine=req.form.get('machine'),
                                      hash_alg=req.form.get('hashalg', 'sha512'))
                    return await return_tarball(req, workdir)
        log_signing_audit('module_sign', 'failure', machine=req.form.get('machine'),
                          hash_alg=req.form.get('hashalg', 'sha512'))
        return text("Signing error", status=500)

    @app.post("/sign/tegra/uefi")
    async def sign_handler_uefi(req: request):
        f = validate_upload(req, "artifact")
        if not f:
            return text("Invalid artifact", status=400)
        with tempfile.TemporaryDirectory() as workdir:
            try:
                s = UefiSigner(app,
                               workdir,
                               req.form.get("machine"),
                               req.form.get("signing_type"))
            except ValueError:
                return text("Invalid parameters", status=400)

            signing_type = req.form.get("signing_type").lower()
            if signing_type not in ["sbsign", "signature", "attach_signature"]:
                return text("Invalid signing type", status=400)
            with open(os.path.join(workdir, "artifact"), "wb") as artifact:
                artifact.write(f.body)
            outfile = tempfile.NamedTemporaryFile(delete=False)
            outfile.close()
            if await asyncio.get_running_loop().run_in_executor(None,
                                                                s.sign,
                                                                artifact.name,
                                                                outfile.name):
                log_signing_audit('uefi_sign', 'success', machine=req.form.get('machine'),
                                  signing_type=req.form.get('signing_type'))
                await return_file(req, outfile.name, "artifact.signed")
                response = None
            else:
                log_signing_audit('uefi_sign', 'failure', machine=req.form.get('machine'),
                                  signing_type=req.form.get('signing_type'))
                response = text("Signing error", status=500)
        os.unlink(outfile.name)
        return response

    @app.post("/sign/tegra/ueficapsule")
    async def sign_handler_uefi_capsule(req: request):
        f = validate_upload(req, "artifact")
        if not f:
            return text("Invalid artifact", status=400)
        with tempfile.TemporaryDirectory() as workdir:
            try:
                s = UefiCapsuleSigner(
                    app,
                    workdir,
                    req.form.get("machine"),
                    req.form.get("soctype"),
                    req.form.get("bspversion"),
                    req.form.get("guid"))
            except ValueError:
                return text("Invalid parameters", status=400)

            with open(os.path.join(workdir, "artifact"), "wb") as artifact:
                artifact.write(f.body)
            outfile = tempfile.NamedTemporaryFile(delete=False)
            outfile.close()
            if await asyncio.get_running_loop().run_in_executor(None,
                                                                s.generate_signed_capsule,
                                                                artifact.name,
                                                                outfile.name):
                log_signing_audit('uefi_capsule_sign', 'success', machine=req.form.get('machine'),
                                  soctype=req.form.get('soctype'), bsp_version=req.form.get('bspversion'))
                await return_file(req, outfile.name, "artifact.cap")
                response = None
            else:
                log_signing_audit('uefi_capsule_sign', 'failure', machine=req.form.get('machine'),
                                  soctype=req.form.get('soctype'), bsp_version=req.form.get('bspversion'))
                response = text("Signing error", status=500)
        os.unlink(outfile.name)
        return response

    @app.post("/sign/optee")
    async def sign_handler_optee(req: request):
        f = validate_upload(req, "artifact")
        if not f:
            return text("Invalid artifact", status=400)
        with tempfile.TemporaryDirectory() as workdir:
            try:
                s = OPTEESigner(app, workdir, req.form.get("machine"))
            except ValueError:
                return text("Invalid parameters", status=400)

            if await asyncio.get_running_loop().run_in_executor(None, utils.extract_files, workdir, f):
                result = await asyncio.get_running_loop().run_in_executor(None, s.sign)
                if result:
                    log_signing_audit('optee_sign', 'success', machine=req.form.get('machine'))
                    return await return_tarball(req, workdir)
        log_signing_audit('optee_sign', 'failure', machine=req.form.get('machine'))
        return text("Signing error", status=500)

    @app.post("/sign/rkoptee-tee")
    async def sign_handler_rk_optee_tee(req: request):
        f = validate_upload(req, "artifact")
        if not f:
            return text("Invalid artifact", status=400)
        with tempfile.TemporaryDirectory() as workdir:
            try:
                s = RockchipOpteeSigner(app, workdir, req.form.get("machine"))
            except ValueError:
                return text("Invalid parameters", status=400)
            with open(os.path.join(workdir, "tee.bin"), "wb") as artifact:
                artifact.write(f.body)
            outfile = tempfile.NamedTemporaryFile(delete=False)
            outfile.close()
            if await asyncio.get_running_loop().run_in_executor(None, s.resign_tee,
                                                                os.path.join(workdir, "tee.bin"),
                                                                outfile.name):
                log_signing_audit('rockchip_optee_tee_sign', 'success', machine=req.form.get('machine'))
                await return_file(req, outfile.name, "tee.bin.signed")
                response = None
            else:
                log_signing_audit('rockchip_optee_tee_sign', 'failure', machine=req.form.get('machine'))
                response = text("Signing error", status=500)
        os.unlink(outfile.name)
        return response

    @app.post("/sign/rkoptee-ta")
    async def sign_handler_rk_optee_ta(req: request):
        f = validate_upload(req, "artifact")
        if not f:
            return text("Invalid artifact", status=400)
        with tempfile.TemporaryDirectory() as workdir:
            try:
                s = RockchipOpteeSigner(app, workdir, req.form.get("machine"))
            except ValueError:
                return text("Invalid parameters", status=400)

            if await asyncio.get_running_loop().run_in_executor(None, utils.extract_files, workdir, f):
                result = await asyncio.get_running_loop().run_in_executor(None, s.resign_tas)
                if result:
                    log_signing_audit('rockchip_optee_ta_sign', 'success', machine=req.form.get('machine'))
                    return await return_tarball(req, workdir)
        log_signing_audit('rockchip_optee_ta_sign', 'failure', machine=req.form.get('machine'))
        return text("Signing error", status=500)

    @app.post("/sign/swupdate")
    async def sign_handler_swupdate(req: request):
        distro = req.form.get("distro")
        if not distro:
            return text("Distro name missing", status=400)
        backend = req.form.get("backend")
        method = req.form.get("method")
        if not method:
            method = "RSA"
        key_uri = req.form.get("key-uri")
        if backend == "pkcs11" and not key_uri:
            return text("Key URI missing for PKCS#11 backend", status=400)
        f = validate_upload(req, "sw-description")
        if not f:
            return text("Invalid sw-description", status=400)
        with tempfile.TemporaryDirectory() as workdir:
            try:
                s = SwupdateSigner(app, workdir, distro, backend)
            except ValueError:
                logger.info("could not init signer")
                return text("Invalid parameters", status=400)
            outfile = tempfile.NamedTemporaryFile(delete=False)
            outfile.close()
            with open(os.path.join(workdir, "sw-description"), "w") as infile:
                infile.write(f.body.decode('UTF-8'))
            if await asyncio.get_running_loop().run_in_executor(None, s.sign,
                                                                method, "sw-description",
                                                                outfile.name, key_uri):
                log_signing_audit('swupdate_sign', 'success', distro=distro, backend=backend, method=method)
                await return_file(req, outfile.name, "sw-description.sig")
                response = None
            else:
                log_signing_audit('swupdate_sign', 'failure', distro=distro, backend=backend, method=method)
                response = text("Signing error", status=500)
        os.unlink(outfile.name)
        return response

    @app.post("/sign/mender")
    async def sign_handler_mender(req: request):
        artifact = req.form.get('artifact-uri')
        if not artifact:
            return text("Artifact URI missing", status=400)
        distro = req.form.get('distro')
        if not distro:
            return text("Distro name missing", status=400)
        with tempfile.TemporaryDirectory() as workdir:
            try:
                s = MenderSigner(app, workdir, distro, artifact)
            except ValueError:
                return text("Invalid parameters", status=400)
            if await asyncio.get_running_loop().run_in_executor(None, s.sign):
                log_signing_audit('mender_sign', 'success', distro=distro)
                return text("Signing successful")
        log_signing_audit('mender_sign', 'failure', distro=distro)
        return text("Signing error", status=500)


    @app.post("/sign/tegra/ekb")
    async def get_handler_ekb(req: request):
        with tempfile.TemporaryDirectory() as workdir:
            try:
                s = EKBSigner(
                    app,
                    workdir,
                    req.form.get("machine"),
                    req.form.get("soctype"),
                    req.form.get("bspversion"))
            except ValueError:
                return text("Invalid parameters", status=400)

            outfile = tempfile.NamedTemporaryFile(delete=False)
            outfile.close()
            if await asyncio.get_running_loop().run_in_executor(None,
                                                                s.generate_ekb,
                                                                outfile.name):
                log_signing_audit('ekb_sign', 'success', machine=req.form.get('machine'),
                                  soctype=req.form.get('soctype'), bsp_version=req.form.get('bspversion'))
                await return_file(req, outfile.name, "ekb.img")
                response = None
            else:
                log_signing_audit('ekb_sign', 'failure', machine=req.form.get('machine'),
                                  soctype=req.form.get('soctype'), bsp_version=req.form.get('bspversion'))
                response = text("Signing error", status=500)
        os.unlink(outfile.name)
        return response

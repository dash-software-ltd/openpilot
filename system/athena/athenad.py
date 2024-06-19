#!/usr/bin/env python3
from __future__ import annotations
import base64
import bz2
import hashlib
import io
import json
import os
import queue
import random
import select
import socket
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, replace
from datetime import datetime
from functools import partial
from queue import Queue
from typing import cast
from collections.abc import Callable
import requests
from jsonrpc import JSONRPCResponseManager, dispatcher
from websocket import ABNF, WebSocket, WebSocketException, WebSocketTimeoutException, create_connection
import cereal.messaging as messaging
from cereal import log
from cereal.services import SERVICE_LIST
from openpilot.common.api import Api
from openpilot.common.file_helpers import CallbackReader
from openpilot.common.params import Params
from openpilot.common.realtime import set_core_affinity
from openpilot.system.hardware import HARDWARE, PC
from openpilot.system.loggerd.xattr_cache import getxattr, setxattr
from openpilot.common.swaglog import cloudlog
from openpilot.system.version import get_build_metadata
from openpilot.system.hardware.hw import Paths
ATHENA_HOST = os.getenv('ATHENA_HOST', 'wss://athena.comma.ai')
HANDLER_THREADS = int(os.getenv('HANDLER_THREADS', '4'))
LOCAL_PORT_WHITELIST = {8022}
LOG_ATTR_NAME = 'user.upload'
LOG_ATTR_VALUE_MAX_UNIX_TIME = int.to_bytes(2147483647, 4, sys.byteorder)
RECONNECT_TIMEOUT_S = 70
RETRY_DELAY = 10
MAX_RETRY_COUNT = 30
MAX_AGE = 31 * 24 * 3600
WS_FRAME_SIZE = 4096
NetworkType = log.DeviceState.NetworkType
UploadFileDict = dict[str, str | int | float | bool]
UploadItemDict = dict[str, str | bool | int | float | dict[str, str]]
UploadFilesToUrlResponse = dict[str, int | list[UploadItemDict] | list[str]]

@dataclass
class UploadFile:
    fn: str
    url: str
    headers: dict[str, str]
    allow_cellular: bool

    @classmethod
    def from_dict(cls, d: dict) -> UploadFile:
        return cls(d.get('fn', ''), d.get('url', ''), d.get('headers', {}), d.get('allow_cellular', False))

@dataclass
class UploadItem:
    path: str
    url: str
    headers: dict[str, str]
    created_at: int
    id: str | None
    retry_count: int = 0
    current: bool = False
    progress: float = 0
    allow_cellular: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> UploadItem:
        return cls(d['path'], d['url'], d['headers'], d['created_at'], d['id'], d['retry_count'], d['current'], d['progress'], d['allow_cellular'])
dispatcher['echo'] = lambda s: s
recv_queue: Queue[str] = queue.Queue()
send_queue: Queue[str] = queue.Queue()
upload_queue: Queue[UploadItem] = queue.Queue()
low_priority_send_queue: Queue[str] = queue.Queue()
log_recv_queue: Queue[str] = queue.Queue()
cancelled_uploads: set[str] = set()
cur_upload_items: dict[int, UploadItem | None] = {}

def strip_bz2_extension(fn: str) -> str:
    if fn.endswith('.bz2'):
        return fn[:-4]
    return fn

class AbortTransferException(Exception):
    pass

class UploadQueueCache:

    @staticmethod
    def initialize(upload_queue: Queue[UploadItem]) -> None:
        try:
            upload_queue_json = Params().get('AthenadUploadQueue')
            if upload_queue_json is not None:
                for item in json.loads(upload_queue_json):
                    upload_queue.put(UploadItem.from_dict(item))
        except Exception:
            cloudlog.exception('athena.UploadQueueCache.initialize.exception')

    @staticmethod
    def cache(upload_queue: Queue[UploadItem]) -> None:
        try:
            queue: list[UploadItem | None] = list(upload_queue.queue)
            items = [asdict(i) for i in queue if i is not None and i.id not in cancelled_uploads]
            Params().put('AthenadUploadQueue', json.dumps(items))
        except Exception:
            cloudlog.exception('athena.UploadQueueCache.cache.exception')

def handle_long_poll(ws: WebSocket, exit_event: threading.Event | None) -> None:
    end_event = threading.Event()
    threads = [threading.Thread(target=ws_manage, args=(ws, end_event), name='ws_manage'), threading.Thread(target=ws_recv, args=(ws, end_event), name='ws_recv'), threading.Thread(target=ws_send, args=(ws, end_event), name='ws_send'), threading.Thread(target=upload_handler, args=(end_event,), name='upload_handler'), threading.Thread(target=log_handler, args=(end_event,), name='log_handler'), threading.Thread(target=stat_handler, args=(end_event,), name='stat_handler')] + [threading.Thread(target=jsonrpc_handler, args=(end_event,), name=f'worker_{x}') for x in range(HANDLER_THREADS)]
    for thread in threads:
        thread.start()
    try:
        while not end_event.wait(0.1):
            if exit_event is not None and exit_event.is_set():
                end_event.set()
    except (KeyboardInterrupt, SystemExit):
        end_event.set()
        raise
    finally:
        for thread in threads:
            cloudlog.debug(f'athena.joining {thread.name}')
            thread.join()

def jsonrpc_handler(end_event: threading.Event) -> None:
    dispatcher['startLocalProxy'] = partial(startLocalProxy, end_event)
    while not end_event.is_set():
        try:
            data = recv_queue.get(timeout=1)
            if 'method' in data:
                cloudlog.event('athena.jsonrpc_handler.call_method', data=data)
                response = JSONRPCResponseManager.handle(data, dispatcher)
                send_queue.put_nowait(response.json)
            elif 'id' in data and ('result' in data or 'error' in data):
                log_recv_queue.put_nowait(data)
            else:
                raise Exception('not a valid request or response')
        except queue.Empty:
            pass
        except Exception as e:
            cloudlog.exception('athena jsonrpc handler failed')
            send_queue.put_nowait(json.dumps({'error': str(e)}))

def retry_upload(tid: int, end_event: threading.Event, increase_count: bool=True) -> None:
    item = cur_upload_items[tid]
    if item is not None and item.retry_count < MAX_RETRY_COUNT:
        new_retry_count = item.retry_count + 1 if increase_count else item.retry_count
        item = replace(item, retry_count=new_retry_count, progress=0, current=False)
        upload_queue.put_nowait(item)
        UploadQueueCache.cache(upload_queue)
        cur_upload_items[tid] = None
        for _ in range(RETRY_DELAY):
            time.sleep(1)
            if end_event.is_set():
                break

def cb(sm, item, tid, end_event: threading.Event, sz: int, cur: int) -> None:
    sm.update(0)
    metered = sm['deviceState'].networkMetered
    if metered and (not item.allow_cellular):
        raise AbortTransferException
    if end_event.is_set():
        raise AbortTransferException
    cur_upload_items[tid] = replace(item, progress=cur / sz if sz else 1)

def upload_handler(end_event: threading.Event) -> None:
    sm = messaging.SubMaster(['deviceState'])
    tid = threading.get_ident()
    while not end_event.is_set():
        cur_upload_items[tid] = None
        try:
            cur_upload_items[tid] = item = replace(upload_queue.get(timeout=1), current=True)
            if item.id in cancelled_uploads:
                cancelled_uploads.remove(item.id)
                continue
            age = datetime.now() - datetime.fromtimestamp(item.created_at / 1000)
            if age.total_seconds() > MAX_AGE:
                cloudlog.event('athena.upload_handler.expired', item=item, error=True)
                continue
            sm.update(0)
            metered = sm['deviceState'].networkMetered
            network_type = sm['deviceState'].networkType.raw
            if metered and (not item.allow_cellular):
                retry_upload(tid, end_event, False)
                continue
            try:
                fn = item.path
                try:
                    sz = os.path.getsize(fn)
                except OSError:
                    sz = -1
                cloudlog.event('athena.upload_handler.upload_start', fn=fn, sz=sz, network_type=network_type, metered=metered, retry_count=item.retry_count)
                response = _do_upload(item, partial(cb, sm, item, tid, end_event))
                if response.status_code not in (200, 201, 401, 403, 412):
                    cloudlog.event('athena.upload_handler.retry', status_code=response.status_code, fn=fn, sz=sz, network_type=network_type, metered=metered)
                    retry_upload(tid, end_event)
                else:
                    cloudlog.event('athena.upload_handler.success', fn=fn, sz=sz, network_type=network_type, metered=metered)
                UploadQueueCache.cache(upload_queue)
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.SSLError):
                cloudlog.event('athena.upload_handler.timeout', fn=fn, sz=sz, network_type=network_type, metered=metered)
                retry_upload(tid, end_event)
            except AbortTransferException:
                cloudlog.event('athena.upload_handler.abort', fn=fn, sz=sz, network_type=network_type, metered=metered)
                retry_upload(tid, end_event, False)
        except queue.Empty:
            pass
        except Exception:
            cloudlog.exception('athena.upload_handler.exception')

def _do_upload(upload_item: UploadItem, callback: Callable=None) -> requests.Response:
    path = upload_item.path
    compress = False
    if not os.path.exists(path) and os.path.exists(strip_bz2_extension(path)):
        path = strip_bz2_extension(path)
        compress = True
    with open(path, 'rb') as f:
        content = f.read()
        if compress:
            cloudlog.event('athena.upload_handler.compress', fn=path, fn_orig=upload_item.path)
            content = bz2.compress(content)
    with io.BytesIO(content) as data:
        return requests.put(upload_item.url, data=CallbackReader(data, callback, len(content)) if callback else data, headers={**upload_item.headers, 'Content-Length': str(len(content))}, timeout=30)

@dispatcher.add_method
def getMessage(service: str, timeout: int=1000) -> dict:
    if service is None or service not in SERVICE_LIST:
        raise Exception('invalid service')
    socket = messaging.sub_sock(service, timeout=timeout)
    ret = messaging.recv_one(socket)
    if ret is None:
        raise TimeoutError
    return cast(dict, ret.to_dict())

@dispatcher.add_method
def getVersion() -> dict[str, str]:
    build_metadata = get_build_metadata()
    return {'version': build_metadata.openpilot.version, 'remote': build_metadata.openpilot.git_normalized_origin, 'branch': build_metadata.channel, 'commit': build_metadata.openpilot.git_commit}

@dispatcher.add_method
def setNavDestination(latitude: int=0, longitude: int=0, place_name: str=None, place_details: str=None) -> dict[str, int]:
    destination = {'latitude': latitude, 'longitude': longitude, 'place_name': place_name, 'place_details': place_details}
    Params().put('NavDestination', json.dumps(destination))
    return {'success': 1}

def scan_dir(path: str, prefix: str) -> list[str]:
    files = []
    with os.scandir(path) as i:
        for e in i:
            rel_path = os.path.relpath(e.path, Paths.log_root())
            if e.is_dir(follow_symlinks=False):
                rel_path = os.path.join(rel_path, '')
                if rel_path.startswith(prefix) or prefix.startswith(rel_path):
                    files.extend(scan_dir(e.path, prefix))
            elif rel_path.startswith(prefix):
                files.append(rel_path)
    return files

@dispatcher.add_method
def listDataDirectory(prefix='') -> list[str]:
    return scan_dir(Paths.log_root(), prefix)

@dispatcher.add_method
def uploadFileToUrl(fn: str, url: str, headers: dict[str, str]) -> UploadFilesToUrlResponse:
    response: UploadFilesToUrlResponse = uploadFilesToUrls([{'fn': fn, 'url': url, 'headers': headers}])
    return response

@dispatcher.add_method
def uploadFilesToUrls(files_data: list[UploadFileDict]) -> UploadFilesToUrlResponse:
    files = map(UploadFile.from_dict, files_data)
    items: list[UploadItemDict] = []
    failed: list[str] = []
    for file in files:
        if len(file.fn) == 0 or file.fn[0] == '/' or '..' in file.fn or (len(file.url) == 0):
            failed.append(file.fn)
            continue
        path = os.path.join(Paths.log_root(), file.fn)
        if not os.path.exists(path) and (not os.path.exists(strip_bz2_extension(path))):
            failed.append(file.fn)
            continue
        url = file.url.split('?')[0]
        if any((url == item['url'].split('?')[0] for item in listUploadQueue())):
            continue
        item = UploadItem(path=path, url=file.url, headers=file.headers, created_at=int(time.time() * 1000), id=None, allow_cellular=file.allow_cellular)
        upload_id = hashlib.sha1(str(item).encode()).hexdigest()
        item = replace(item, id=upload_id)
        upload_queue.put_nowait(item)
        items.append(asdict(item))
    UploadQueueCache.cache(upload_queue)
    resp: UploadFilesToUrlResponse = {'enqueued': len(items), 'items': items}
    if failed:
        resp['failed'] = failed
    return resp

@dispatcher.add_method
def listUploadQueue() -> list[UploadItemDict]:
    items = list(upload_queue.queue) + list(cur_upload_items.values())
    return [asdict(i) for i in items if i is not None and i.id not in cancelled_uploads]

@dispatcher.add_method
def cancelUpload(upload_id: str | list[str]) -> dict[str, int | str]:
    if not isinstance(upload_id, list):
        upload_id = [upload_id]
    uploading_ids = {item.id for item in list(upload_queue.queue)}
    cancelled_ids = uploading_ids.intersection(upload_id)
    if len(cancelled_ids) == 0:
        return {'success': 0, 'error': 'not found'}
    cancelled_uploads.update(cancelled_ids)
    return {'success': 1}

@dispatcher.add_method
def setRouteViewed(route: str) -> dict[str, int | str]:
    params = Params()
    r = params.get('AthenadRecentlyViewedRoutes', encoding='utf8')
    routes = [] if r is None else r.split(',')
    routes.append(route)
    routes = list(dict.fromkeys(routes))
    params.put('AthenadRecentlyViewedRoutes', ','.join(routes[-10:]))
    return {'success': 1}

def startLocalProxy(global_end_event: threading.Event, remote_ws_uri: str, local_port: int) -> dict[str, int]:
    try:
        if local_port not in LOCAL_PORT_WHITELIST:
            raise Exception('Requested local port not whitelisted')
        cloudlog.debug('athena.startLocalProxy.starting')
        dongle_id = Params().get('DongleId').decode('utf8')
        identity_token = Api(dongle_id).get_token()
        ws = create_connection(remote_ws_uri, cookie='jwt=' + identity_token, enable_multithread=True)
        ws.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 144)
        (ssock, csock) = socket.socketpair()
        local_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_sock.connect(('127.0.0.1', local_port))
        local_sock.setblocking(False)
        proxy_end_event = threading.Event()
        threads = [threading.Thread(target=ws_proxy_recv, args=(ws, local_sock, ssock, proxy_end_event, global_end_event)), threading.Thread(target=ws_proxy_send, args=(ws, local_sock, csock, proxy_end_event))]
        for thread in threads:
            thread.start()
        cloudlog.debug('athena.startLocalProxy.started')
        return {'success': 1}
    except Exception as e:
        cloudlog.exception('athenad.startLocalProxy.exception')
        raise e

@dispatcher.add_method
def getPublicKey() -> str | None:
    if not os.path.isfile(Paths.persist_root() + '/comma/id_rsa.pub'):
        return None
    with open(Paths.persist_root() + '/comma/id_rsa.pub') as f:
        return f.read()

@dispatcher.add_method
def getSshAuthorizedKeys() -> str:
    return Params().get('GithubSshKeys', encoding='utf8') or ''

@dispatcher.add_method
def getGithubUsername() -> str:
    return Params().get('GithubUsername', encoding='utf8') or ''

@dispatcher.add_method
def getSimInfo():
    return HARDWARE.get_sim_info()

@dispatcher.add_method
def getNetworkType():
    return HARDWARE.get_network_type()

@dispatcher.add_method
def getNetworkMetered() -> bool:
    network_type = HARDWARE.get_network_type()
    return HARDWARE.get_network_metered(network_type)

@dispatcher.add_method
def getNetworks():
    return HARDWARE.get_networks()

@dispatcher.add_method
def takeSnapshot() -> str | dict[str, str] | None:
    from openpilot.system.camerad.snapshot.snapshot import jpeg_write, snapshot
    ret = snapshot()
    if ret is not None:

        def b64jpeg(x):
            if x is not None:
                f = io.BytesIO()
                jpeg_write(f, x)
                return base64.b64encode(f.getvalue()).decode('utf-8')
            else:
                return None
        return {'jpegBack': b64jpeg(ret[0]), 'jpegFront': b64jpeg(ret[1])}
    else:
        raise Exception('not available while camerad is started')

def get_logs_to_send_sorted() -> list[str]:
    curr_time = int(time.time())
    logs = []
    for log_entry in os.listdir(Paths.swaglog_root()):
        log_path = os.path.join(Paths.swaglog_root(), log_entry)
        time_sent = 0
        try:
            value = getxattr(log_path, LOG_ATTR_NAME)
            if value is not None:
                time_sent = int.from_bytes(value, sys.byteorder)
        except (ValueError, TypeError):
            pass
        if not time_sent or curr_time - time_sent > 3600:
            logs.append(log_entry)
    return sorted(logs)[:-1]

def log_handler(end_event: threading.Event) -> None:
    return

def stat_handler(end_event: threading.Event) -> None:
    return

def ws_proxy_recv(ws: WebSocket, local_sock: socket.socket, ssock: socket.socket, end_event: threading.Event, global_end_event: threading.Event) -> None:
    while not (end_event.is_set() or global_end_event.is_set()):
        try:
            r = select.select((ws.sock,), (), (), 30)
            if r[0]:
                data = ws.recv()
                if isinstance(data, str):
                    data = data.encode('utf-8')
                local_sock.sendall(data)
        except WebSocketTimeoutException:
            pass
        except Exception:
            cloudlog.exception('athenad.ws_proxy_recv.exception')
            break
    cloudlog.debug('athena.ws_proxy_recv closing sockets')
    ssock.close()
    local_sock.close()
    ws.close()
    cloudlog.debug('athena.ws_proxy_recv done closing sockets')
    end_event.set()

def ws_proxy_send(ws: WebSocket, local_sock: socket.socket, signal_sock: socket.socket, end_event: threading.Event) -> None:
    while not end_event.is_set():
        try:
            (r, _, _) = select.select((local_sock, signal_sock), (), ())
            if r:
                if r[0].fileno() == signal_sock.fileno():
                    end_event.set()
                    break
                data = local_sock.recv(4096)
                if not data:
                    end_event.set()
                    break
                ws.send(data, ABNF.OPCODE_BINARY)
        except Exception:
            cloudlog.exception('athenad.ws_proxy_send.exception')
            end_event.set()
    cloudlog.debug('athena.ws_proxy_send closing sockets')
    signal_sock.close()
    cloudlog.debug('athena.ws_proxy_send done closing sockets')

def ws_recv(ws: WebSocket, end_event: threading.Event) -> None:
    while not end_event.is_set():
        try:
            (opcode, data) = ws.recv_data(control_frame=True)
            if opcode == ABNF.OPCODE_TEXT:
                data = data.decode('utf-8')
                recv_queue.put_nowait(data)
        except WebSocketTimeoutException:
            last_ping = int(Params().get('LastAthenaPingTime') or b'0')
            ns_since_last_ping = int(time.monotonic() * 1000000000.0) - last_ping
            if ns_since_last_ping > RECONNECT_TIMEOUT_S * 1000000000.0:
                cloudlog.exception('athenad.ws_recv.timeout')
                end_event.set()
        except Exception:
            cloudlog.exception('athenad.ws_recv.exception')
            end_event.set()

def ws_send(ws: WebSocket, end_event: threading.Event) -> None:
    while not end_event.is_set():
        try:
            try:
                data = send_queue.get_nowait()
            except queue.Empty:
                data = low_priority_send_queue.get(timeout=1)
            for i in range(0, len(data), WS_FRAME_SIZE):
                frame = data[i:i + WS_FRAME_SIZE]
                last = i + WS_FRAME_SIZE >= len(data)
                opcode = ABNF.OPCODE_TEXT if i == 0 else ABNF.OPCODE_CONT
                ws.send_frame(ABNF.create_frame(frame, opcode, last))
        except queue.Empty:
            pass
        except Exception:
            cloudlog.exception('athenad.ws_send.exception')
            end_event.set()

def ws_manage(ws: WebSocket, end_event: threading.Event) -> None:
    params = Params()
    onroad_prev = None
    sock = ws.sock
    while True:
        onroad = params.get_bool('IsOnroad')
        if onroad != onroad_prev:
            onroad_prev = onroad
            if sock is not None:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, 16000 if onroad else 0)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 7 if onroad else 30)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 7 if onroad else 10)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 2 if onroad else 3)
        if end_event.wait(5):
            break

def backoff(retries: int) -> int:
    return random.randrange(0, min(128, int(2 ** retries)))

def main(exit_event: threading.Event=None):
    try:
        set_core_affinity([0, 1, 2, 3])
    except Exception:
        cloudlog.exception('failed to set core affinity')
    params = Params()
    dongle_id = params.get('DongleId', encoding='utf-8')
    UploadQueueCache.initialize(upload_queue)
    ws_uri = ATHENA_HOST + '/ws/v2/' + dongle_id
    api = Api(dongle_id)
    conn_start = None
    conn_retries = 0
    while exit_event is None or not exit_event.is_set():
        try:
            if conn_start is None:
                conn_start = time.monotonic()
            cloudlog.event('athenad.main.connecting_ws', ws_uri=ws_uri, retries=conn_retries)
            ws = create_connection(ws_uri, cookie='jwt=' + api.get_token(), enable_multithread=True, timeout=30.0)
            cloudlog.event('athenad.main.connected_ws', ws_uri=ws_uri, retries=conn_retries, duration=time.monotonic() - conn_start)
            conn_start = None
            conn_retries = 0
            cur_upload_items.clear()
            handle_long_poll(ws, exit_event)
        except (KeyboardInterrupt, SystemExit):
            break
        except (ConnectionError, TimeoutError, WebSocketException):
            conn_retries += 1
            params.remove('LastAthenaPingTime')
        except Exception:
            cloudlog.exception('athenad.main.exception')
            conn_retries += 1
            params.remove('LastAthenaPingTime')
        time.sleep(backoff(conn_retries))
if __name__ == '__main__':
    main()

@dispatcher.add_method
def ping() -> None:
    last_ping = int(time.monotonic() * 1000000000.0)
    Params().put('LastAthenaPingTime', str(last_ping))

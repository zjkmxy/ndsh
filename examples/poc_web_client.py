import json
import logging
import base64
import asyncio as aio
import aiohttp
from aiohttp import web
from ndn import security as sec
from ndn.app_support import security_v2
from ndn import encoding as enc
from ndn import appv2, types
from Cryptodome.PublicKey import ECC
from ndsh.config import SystemConfig
from ndsh.process import FlowKey
from ndsh import ecies


CLIENT_PRIV_KEY = '''
MHcCAQEEILAkIeilbqsbhdzP5WCxE8D/Ij3l/qzZiFXUCga7iEYLoAoGCCqGSM49
AwEHoUQDQgAEPA+aXLym/UijEoFXELRdnOHHvDTDr7mpNs9R+thtSXupvScqoEZ3
GGtiDnpiDwxWKD/a/7YiEaixy69bFnaeYw==
'''
SERVER_CERT = '''
Bv0BOgcyCAluZHNoLXRlc3QIBnNlcnZlcggDS0VZCAhh1ADcx+dm6AgEc2VsZjYI
AAABiToveMkUCRgBAhkEADbugBVbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
upmjrNpSN/TYGCE3OrawScFOuG0Kf/coY+6biKGuymWYoNmr0iXN+uQK5qUqDaeQ
NdkhLtZ+JGUTZJikew5L3BZTGwEDHCQHIggJbmRzaC10ZXN0CAZzZXJ2ZXIIA0tF
WQgIYdQA3MfnZuj9AP0m/QD+DzIwMjMwNzA5VDEwMjUzNv0A/w8yMDQzMDcwNFQx
MDI1MzYXRzBFAiBtj0kZaLZxckmx1Q1McKecuXtemqeKAhT2fipYuChoQQIhAKlG
A08Ubm3X6fKwmhZYrkcRNbTqP4E7pp8boz5NHUjc
'''
CLIENT_CERT = '''
Bv0BOQcyCAluZHNoLXRlc3QIBmNsaWVudAgDS0VZCAjwO3RjxwtX5wgEc2VsZjYI
AAABiTozfkAUCRgBAhkEADbugBVbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
PA+aXLym/UijEoFXELRdnOHHvDTDr7mpNs9R+thtSXupvScqoEZ3GGtiDnpiDwxW
KD/a/7YiEaixy69bFnaeYxZTGwEDHCQHIggJbmRzaC10ZXN0CAZjbGllbnQIA0tF
WQgI8Dt0Y8cLV+f9AP0m/QD+DzIwMjMwNzA5VDEwMzAwMP0A/w8yMDQzMDcwNFQx
MDMwMDAXRjBEAiB+vno4650ZdHYe0p/6CgSNlRd1DePifmyPU/20TN7fFwIgdZ0q
5n9ecDq72oIUDnTK2yghVaZna7nwJs2q6+XgZ3U=
'''
HTML_DATA = '''
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <title> NDSH </title>
    <link href="static/css/xterm.min.css" rel="stylesheet" type="text/css"/>
    <link href="static/css/fullscreen.min.css" rel="stylesheet" type="text/css"/>
  </head>
  <body>
    <div id="terminal"></div>
    <script src="static/js/xterm.min.js"></script>
    <script src="static/js/fullscreen.min.js"></script>
    <script>
        var ws_url = window.location.href.replace('http', 'ws'),
            join = (ws_url[ws_url.length-1] == '/' ? '' : '/'),
            url = ws_url + join + 'ws',
            socket = new WebSocket(url),
            terminal = document.getElementById('#terminal'),
            term = new Terminal({cursorBlink: true});
        console.log('url= ' + url);
        term.on('data', function(data) {
            socket.send(data);
        });
        socket.onopen = function(e) {
            term.open(terminal, true);
            term.toggleFullscreen(true);
        };
        socket.onmessage = function(msg) {
            term.write(msg.data);
        };
        socket.onerror = function(e) {
          console.log(e);
        };
        socket.onclose = function(e) {
          console.log(e);
          // term.destroy();
        };
    </script>
  </body>
</html>
'''


logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')

app = appv2.NDNApp()
client_cert = security_v2.parse_certificate(base64.b64decode(CLIENT_CERT))
client_key_bits = ECC.import_key(base64.b64decode(CLIENT_PRIV_KEY))
signer = sec.Sha256WithEcdsaSigner(client_cert.name, base64.b64decode(CLIENT_PRIV_KEY))
server_cert = security_v2.parse_certificate(base64.b64decode(SERVER_CERT))
server_key_bits = ECC.import_key(bytes(server_cert.content))
flow_name = 'ndsh-test-1'
in_seq = 0
pkt_cache = {}
in_encryptor = None
out_decryptor = None
web_socket_ws = None


async def websocket_handler(request):
    global in_seq, pkt_cache, web_socket_ws
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    if web_socket_ws is None:
        web_socket_ws = ws
    else:
        logging.error('only one connection is allowed')
        await ws.close()
        return

    # signal start
    name = SystemConfig.app_prefix + [
        enc.Component.from_str('start'),
    ]
    await app.express(name, validator=server_validator, lifetime=1000)

    async for msg in ws:
        if msg.type == aiohttp.WSMsgType.TEXT:
            name = SystemConfig.app_prefix + [
                enc.Component.from_str(flow_name),
                enc.Component.from_str('32=IN'),
                enc.Component.from_sequence_num(in_seq),
            ]
            in_seq += 1
            cipher_text = in_encryptor.encrypt(msg.data.encode())
            data_pkt = app.make_data(name, cipher_text, signer, freshness_period=2000)
            pkt_cache[enc.Name.to_bytes(name)] = data_pkt
            logging.debug(f'[{flow_name}] input {in_seq - 1}: {str(msg.data)}')
        elif msg.type == aiohttp.WSMsgType.ERROR:
            logging.error(f'ws connection closed with exception {ws.exception()}')

    logging.error('websocket connection closed')
    return ws


async def html_handler(request):
    return web.Response(
        text=HTML_DATA,
        content_type='text/html',
    )


web_app = web.Application()
web_app.add_routes([
    web.get('/ws', websocket_handler),
    web.static('/static', './static'),
    web.get('/', html_handler),
])

async def server_validator(_name, sig_ptrs, _context) -> appv2.ValidResult:
    sig_info = sig_ptrs.signature_info
    sig_val = sig_ptrs.signature_value_buf
    if not sig_info or not sig_val:
        return appv2.ValidResult.FAIL
    if sig_info.signature_type != enc.SignatureType.SHA256_WITH_ECDSA:
        return appv2.ValidResult.FAIL
    if sig_info.key_locator.name != server_cert.name:
        return appv2.ValidResult.FAIL
    if not sec.verify_ecdsa(server_key_bits, sig_ptrs):
        return appv2.ValidResult.FAIL
    return appv2.ValidResult.PASS


async def main():
    global in_encryptor, out_decryptor, in_seq

    await app.register(SystemConfig.app_prefix)

    # receive keys
    name = SystemConfig.app_prefix + [
        enc.Component.from_str(flow_name),
        enc.Component.from_str('32=CK-ENC-BY'),
        enc.Component.from_bytes(enc.Name.to_bytes(client_cert.name)),
    ]
    try:
        _, cipher_keys, _ = await app.express(name, validator=server_validator)
    except (types.InterestNack, types.InterestTimeout, types.InterestCanceled, types.ValidationFailure) as e:
        logging.critical(f'Failed to fetch flow key {e}')
        exit(1)

    flow_key = FlowKey.from_bytes(ecies.decrypt(client_key_bits, bytes(cipher_keys)))
    in_encryptor, out_decryptor = flow_key.ciphers()

    # register input
    def input_handler(int_name, _app_param, reply, _context):
        name_bytes = enc.Name.to_bytes(int_name)
        ret = pkt_cache.get(name_bytes, None)
        if ret:
            reply(ret)

    name = SystemConfig.app_prefix + [
        enc.Component.from_str(flow_name),
        enc.Component.from_str('32=IN'),
    ]
    await app.register(SystemConfig.app_prefix)
    app.attach_handler(name, input_handler)

    # start web app
    web_task = aio.create_task(web._run_app(
        web_app,
        host='localhost',
        port=8081,
    ))

    # decode all
    eof_signal = False
    out_seq = 0
    while not eof_signal:
        name = SystemConfig.app_prefix + [
            enc.Component.from_str(flow_name),
            enc.Component.from_str('32=OUT'),
            enc.Component.from_sequence_num(out_seq),
        ]
        try:
            _, cipher_text, context = await app.express(name, server_validator, lifetime=100)
        except types.InterestTimeout:
            logging.debug(f'[{flow_name}] output {out_seq} timeout.')
            # Too short lifetime will trigger a race condition in python-ndn
            continue  # timeout is usual
        except (types.InterestNack, types.ValidationFailure) as e:
            logging.warning(f'[{flow_name}] Fail to fetch output {out_seq}: {e}')
            continue
        except types.InterestCanceled:
            logging.fatal('Local NFD node is down. This PoC version will not handle forwarder failure.')
            exit(1)
        meta_info = context['meta_info']
        if (meta_info is not None
                and meta_info.final_block_id == enc.Component.from_sequence_num(out_seq)):
            eof_signal = True
            logging.debug(f'[{flow_name}] output {out_seq}: EOF')
        else:
            out_seq += 1
        if cipher_text:
            ret = out_decryptor.decrypt(cipher_text)
            logging.debug(f'[{flow_name}] output {out_seq - 1}: {str(ret)}')
            if web_socket_ws is not None:
                await web_socket_ws.send_str(ret.decode())

    # Fetch done
    name = SystemConfig.app_prefix + [
        enc.Component.from_str(flow_name),
        enc.Component.from_str('32=DONE'),
    ]
    try:
        _, done_content, _ = await app.express(name, validator=server_validator)
        done_data = json.loads(bytes(done_content))
        await web_socket_ws.send_str(f'Program exited with {done_data["exit_code"]}')
    except (types.InterestNack, types.InterestTimeout, types.InterestCanceled, types.ValidationFailure) as e:
        logging.critical(f'Failed to fetch done packet {e}')

    # Quit
    await web_socket_ws.close()
    web_task.cancel()
    app.shutdown()


if __name__ == '__main__':
    app.run_forever(after_start=main())

import logging
import os
import base64
import asyncio as aio
from ndn import security as sec
from ndn.app_support import security_v2
from ndn import encoding as enc
from ndn import appv2
from ndsh.config import SystemConfig
from ndsh.executor import Executor
from ndsh.process import Process


SERVER_PRIV_KEY = '''
MHcCAQEEIBaiz+g3UKNFn8W0TjKHH5GKDIQaI9n3eZt51ujKtjVYoAoGCCqGSM49
AwEHoUQDQgAEupmjrNpSN/TYGCE3OrawScFOuG0Kf/coY+6biKGuymWYoNmr0iXN
+uQK5qUqDaeQNdkhLtZ+JGUTZJikew5L3A==
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


logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')

app = appv2.NDNApp()


async def main():
    user = os.environ['USER']
    pwd = os.environ['HOME']
    cmd = os.environ['SHELL']
    args = []
    server_cert = security_v2.parse_certificate(base64.b64decode(SERVER_CERT))
    signer = sec.Sha256WithEcdsaSigner(server_cert.name, base64.b64decode(SERVER_PRIV_KEY))
    client_cert = base64.b64decode(CLIENT_CERT)

    executor = Executor('ndsh-test-1', user, pwd, cmd, args)
    proc = Process(executor, signer, client_cert, app)
    proc.prepare()

    await app.register(SystemConfig.app_prefix)

    def request_handler(int_name, _app_param, reply, _context):
        logging.info("Process started")
        aio.create_task(proc.start())
        app.detach_handler(int_name)
        reply(app.make_data(int_name, b'started', signer, freshness_period=2000))

    name = SystemConfig.app_prefix + [
        enc.Component.from_str('start'),
    ]
    app.attach_handler(name, request_handler)


if __name__ == '__main__':
    app.run_forever(after_start=main())

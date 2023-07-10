import json
import logging
import secrets
from dataclasses import dataclass
from Cryptodome.PublicKey import ECC
from Cryptodome.Cipher import AES
from ndn import appv2, types
from ndn import encoding as enc
from ndn import security as sec
from ndn.app_support import security_v2
from .config import SystemConfig
from .executor import Executor
from . import ecies


@dataclass
class FlowKey:
    in_key: bytes
    in_nonce: bytes
    out_key: bytes
    out_nonce: bytes

    @staticmethod
    def from_bytes(buf: bytes):
        if len(buf) != 56:
            raise RuntimeError(f'Invalid session keys {buf.hex()}')
        return FlowKey(
            in_key=buf[0:16],
            out_key=buf[16:32],
            in_nonce=buf[32:44],
            out_nonce=buf[44:56],
        )

    def to_bytes(self):
        return self.in_key + self.out_key + self.in_nonce + self.out_nonce

    def ciphers(self):
        in_cipher = AES.new(self.in_key, AES.MODE_CTR,
                            nonce=self.in_nonce, initial_value=1)
        out_cipher = AES.new(self.out_key, AES.MODE_CTR,
                             nonce=self.out_nonce, initial_value=1)
        return in_cipher, out_cipher

    @staticmethod
    def generate():
        return FlowKey(
            in_key=secrets.token_bytes(16),
            out_key=secrets.token_bytes(16),
            in_nonce=secrets.token_bytes(12),
            out_nonce=secrets.token_bytes(12),
        )


class Process:
    flow_name: str
    flow_key: FlowKey
    app: appv2.NDNApp
    client_key_name: enc.FormalName
    client_key_bits: ECC.EccKey
    signer: sec.Sha256WithEcdsaSigner
    packet_cache: dict[bytes, bytes]
    executor: Executor
    in_seq: int = 0
    out_seq: int = 0
    done: bool = False
    no_more_input: bool = False
    out_encryptor = None
    in_decryptor = None

    def __init__(self, executor: Executor, signer: sec.Sha256WithEcdsaSigner, client_cert: bytes,
                 app: appv2.NDNApp):
        self.packet_cache = {}
        self.flow_name = executor.flow_name
        self.executor = executor
        self.flow_key = FlowKey.generate()
        self.signer = signer
        cert = security_v2.parse_certificate(client_cert)
        self.client_key_name = cert.name
        self.client_key_bits = ECC.import_key(bytes(cert.content))
        self.app = app

    def key_handler(self, name, _app_param, reply, _context):
        name_bytes = enc.Name.to_bytes(name)
        ret = self.packet_cache.get(name_bytes, None)
        if ret:
            reply(ret)

    def output_handler(self, name, _app_param, reply, _context):
        name_bytes = enc.Name.to_bytes(name)
        ret = self.packet_cache.get(name_bytes, None)
        if ret:
            reply(ret)

    async def input_validator(self, _name, sig_ptrs, _context) -> appv2.ValidResult:
        # name is fixed so no need to check
        sig_info = sig_ptrs.signature_info
        sig_val = sig_ptrs.signature_value_buf
        if not sig_info or not sig_val:
            return appv2.ValidResult.FAIL
        if sig_info.signature_type != enc.SignatureType.SHA256_WITH_ECDSA:
            return appv2.ValidResult.FAIL
        if sig_info.key_locator.name != self.client_key_name:
            return appv2.ValidResult.FAIL
        if not sec.verify_ecdsa(self.client_key_bits, sig_ptrs):
            return appv2.ValidResult.FAIL
        return appv2.ValidResult.PASS

    async def feed_input(self) -> bytes:
        while not self.no_more_input and not self.done:
            name = SystemConfig.app_prefix + [
                enc.Component.from_str(self.flow_name),
                enc.Component.from_str('32=IN'),
                enc.Component.from_sequence_num(self.in_seq),
            ]
            try:
                _, cipher_text, context = await self.app.express(
                    name, self.input_validator, lifetime=100)
            except types.InterestTimeout:
                logging.debug(f'[{self.flow_name}] input {self.in_seq} timeout.')
                continue  # timeout is usual
            except (types.InterestNack, types.ValidationFailure) as e:
                logging.warning(f'[{self.flow_name}] Fail to fetch input {self.in_seq}: {e}')
                continue
            except types.InterestCanceled:
                logging.fatal('Local NFD node is down. This PoC version will not handle forwarder failure.')
                exit(1)
            meta_info = context['meta_info']
            if (meta_info is not None
                    and meta_info.final_block_id == enc.Component.from_sequence_num(self.in_seq)):
                self.no_more_input = True
                logging.debug(f'[{self.flow_name}] input {self.in_seq}: EOF')
            else:
                self.in_seq += 1
            if cipher_text:
                ret = self.in_decryptor.decrypt(cipher_text)
                logging.debug(f'[{self.flow_name}] input {self.in_seq-1}: {str(ret)}')
                return ret
            else:
                logging.debug(f'[{self.flow_name}] input {self.in_seq}: (empty)')
                return b''

    def stdout_writer(self, data: bytes):
        name = SystemConfig.app_prefix + [
            enc.Component.from_str(self.flow_name),
            enc.Component.from_str('32=OUT'),
            enc.Component.from_sequence_num(self.out_seq),
        ]
        self.out_seq += 1
        cipher_text = self.out_encryptor.encrypt(data)
        data_pkt = self.app.make_data(name, cipher_text, self.signer, freshness_period=2000)
        self.packet_cache[enc.Name.to_bytes(name)] = data_pkt
        logging.debug(f'[{self.flow_name}] output {self.out_seq-1}: {str(data)}')

    def notify_finish(self, code):
        logging.info(f'[{self.flow_name}] finished with {code}.')
        self.done = True
        # Last output packet
        name = SystemConfig.app_prefix + [
            enc.Component.from_str(self.flow_name),
            enc.Component.from_str('32=OUT'),
            enc.Component.from_sequence_num(self.out_seq),
        ]
        data_pkt = self.app.make_data(name, b'', self.signer,
                                      freshness_period=10000,
                                      final_block_id=enc.Component.from_sequence_num(self.out_seq))
        self.packet_cache[enc.Name.to_bytes(name)] = data_pkt
        # DONE packet
        name = SystemConfig.app_prefix + [
            enc.Component.from_str(self.flow_name),
            enc.Component.from_str('32=DONE'),
        ]
        data = json.dumps({
            'last_in_seq': self.in_seq,
            'last_out_seq': self.out_seq,
            'exit_code': code,
        })
        data_pkt = self.app.make_data(name, data.encode(), self.signer,
                                      freshness_period=10000,
                                      final_block_id=enc.Component.from_sequence_num(self.out_seq))
        self.packet_cache[enc.Name.to_bytes(name)] = data_pkt

    def prepare(self):
        # flow key packet
        cipher_keys = ecies.encrypt(self.client_key_bits, self.flow_key.to_bytes())
        name = SystemConfig.app_prefix + [
            enc.Component.from_str(self.flow_name),
            enc.Component.from_str('32=CK-ENC-BY'),
            enc.Component.from_bytes(enc.Name.to_bytes(self.client_key_name)),
        ]
        data_pkt = self.app.make_data(name, cipher_keys, self.signer, freshness_period=10000)
        self.packet_cache[enc.Name.to_bytes(name)] = data_pkt
        # register handlers
        self.app.attach_handler(name, self.key_handler)
        name = SystemConfig.app_prefix + [
            enc.Component.from_str(self.flow_name),
            enc.Component.from_str('32=OUT'),
        ]
        self.app.attach_handler(name, self.output_handler)
        name = SystemConfig.app_prefix + [
            enc.Component.from_str(self.flow_name),
            enc.Component.from_str('32=DONE'),
        ]
        self.app.attach_handler(name, self.output_handler)
        # setup encryptors
        self.in_decryptor, self.out_encryptor = self.flow_key.ciphers()

    async def start(self):
        await self.executor.start(self.feed_input, self.stdout_writer, self.notify_finish)

import pwd
import asyncio as aio
from .config import SystemConfig

## Abadoned
class DataProtocol(aio.SubprocessProtocol):
    def __init__(self, exit_future):
        self.exit_future = exit_future
        self.output = bytearray()

    def pipe_data_received(self, fd, data):
        print('DATA:', data)
        self.output.extend(data)

    def process_exited(self):
        self.exit_future.set_result(True)



class Process:
    flow_name: str
    user_name: str
    uid: int
    pid: int
    cmd: str
    args: list[str]
    cwd: str
    proto: aio.SubprocessProtocol
    trans: aio.SubprocessTransport
    running: bool = False

    def __init__(self, flow_name: str, user_name: str, cwd: str, cmd: str, args: list[str]):
        self.flow_name = flow_name
        self.user_name = user_name
        self.cwd = cwd
        self.cmd = cmd
        self.args = args.copy()
        try:
            pw_record = pwd.getpwnam(user_name)
        except (KeyError, RuntimeError, PermissionError) as exc:
            raise RuntimeError(f'Unable to get user {user_name}') from exc
        self.uid = pw_record.pw_uid
        self.gid = pw_record.pw_gid
        self.proto = None
        self.trans = None

    async def start(self):
        if self.running:
            raise RuntimeError(f'Process {self.flow_name} is already running')
        try:
            # proc = await aio.create_subprocess_exec(
            #     cmd, *args, user=self.uid, group=self.gid, cwd=cwd,
            #     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            loop = aio.get_running_loop()
            future = aio.Future(loop=loop)
            self.trans, self.proto = await loop.subprocess_exec(
                lambda: DataProtocol(future),
                self.cmd, *self.args, user=self.uid, group=self.gid, cwd=self.cwd,
                text=False, bufsize=0,
                stdin=aio.subprocess.PIPE, stdout=aio.subprocess.PIPE, stderr=aio.subprocess.STDOUT)
        except (PermissionError, FileNotFoundError, RuntimeError) as exc:
            raise RuntimeError(f'Unable to run {self.cmd} as user {self.user_name}') from exc
        self.running = True

    async def run(self, stdin_reader, stdout_writer, notify_finish):
        if not self.running:
            raise RuntimeError(f'The process {self.cmd} as user {self.user_name} has not been started')
        stdin_task = None
        while not self.trans.get_pipe_transport(1).is_closing():
            if stdin_task is None:
                stdin_task = aio.create_task(stdin_reader())
            wait_task = aio.create_task(self.trans._wait())
            _done, _pending = await aio.wait([wait_task, stdin_task], return_when=aio.FIRST_COMPLETED)
            if stdin_task.done():
                self.trans.get_pipe_transport(0).write(stdin_task.result())
                # self.proc.stdin.write(stdin_task.result())
                stdin_task = None
        await wait_task
        self.running = False
        notify_finish()

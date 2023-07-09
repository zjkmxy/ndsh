import os
import typing
import pwd
import pty
import subprocess
import asyncio as aio
from .config import SystemConfig


class Executor:
    flow_name: str
    user_name: str
    uid: int
    pid: int
    cmd: str
    args: list[str]
    cwd: str
    running: bool = False
    proc: aio.subprocess.Process | None = None
    std_reader: aio.StreamReader | None = None
    stdio: typing.BinaryIO | None = None
    pmaster: int = -1
    pslave: int = -1

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

    async def start(self, stdin_reader, stdout_writer, notify_finish):
        if self.running:
            raise RuntimeError(f'Process {self.flow_name} is already running')
        try:
            self.pmaster, self.pslave = pty.openpty()
            self.proc = await aio.create_subprocess_exec(
                self.cmd, *self.args, user=self.uid, group=self.gid, cwd=self.cwd,
                text=False, bufsize=0,
                stdin=self.pslave, stdout=self.pslave, stderr=subprocess.STDOUT,
            )

            self.stdio = os.fdopen(self.pmaster, 'w+b')
            loop = aio.get_running_loop()
            self.std_reader = aio.StreamReader()
            protocol = aio.StreamReaderProtocol(self.std_reader)
            await loop.connect_read_pipe(lambda: protocol, self.stdio)

        except (PermissionError, FileNotFoundError, RuntimeError) as exc:
            raise RuntimeError(f'Unable to run {self.cmd} as user {self.user_name}') from exc
        self.running = True
        loop.create_task(self._run(stdin_reader, stdout_writer, notify_finish))

    async def _run(self, stdin_reader, stdout_writer, notify_finish):
        if not self.running:
            raise RuntimeError(f'The process {self.cmd} as user {self.user_name} has not been started')
        stdout_task = None
        stdin_task = None
        buf_len = SystemConfig.stream_buffer_size
        liveness_task = aio.create_task(self.proc.wait())
        while not self.std_reader.at_eof():
            if stdout_task is None:
                stdout_task = aio.create_task(self.std_reader.read(buf_len))
            if stdin_task is None:
                stdin_task = aio.create_task(stdin_reader())
            await aio.wait([stdout_task, stdin_task, liveness_task], return_when=aio.FIRST_COMPLETED)
            if stdin_task.done():
                if stdin_task.result() is not None:
                    self.stdio.write(stdin_task.result())
                    self.stdio.flush()
                stdin_task = None
            if stdout_task.done():
                stdout_writer(stdout_task.result())
                stdout_task = None
            if liveness_task.done():
                break
        self.running = False
        notify_finish(liveness_task.result())
        os.close(self.pmaster)
        os.close(self.pslave)

    async def kill(self):
        if not self.running:
            raise RuntimeError(f'The process {self.cmd} as user {self.user_name} has not been started')
        self.proc.kill()

import pwd
import subprocess
import sys
import asyncio as aio


class Executor:
    user_name: str
    uid: int
    pid: int

    def __init__(self, user_name: str):
        pw_record = pwd.getpwnam(user_name)  # TODO: Handle errors
        self.user_name = pw_record.pw_name
        self.uid = pw_record.pw_uid
        self.gid = pw_record.pw_gid

    async def run(self, cwd: str, cmd: str, args: list[str]):
        try:
            # proc = await aio.create_subprocess_exec(
            #     cmd, *args, user=self.uid, group=self.gid, cwd=cwd,
            #     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            proc = await aio.create_subprocess_exec(
                cmd, *args, user=self.uid, group=self.gid, cwd=cwd)
        except PermissionError as e:
            print(f'Unable to run as user {self.user_name}: {e}')
            return
        await proc.wait()
        print('finished ' + str(cmd))

import sys

import asyncio as aio
from ndsh.process import Process


async def main(my_args: list[str] = None):
    if not my_args:
        my_args = sys.argv[1:]
    user_name, cwd, cmd = my_args[:3]
    args = my_args[3:]
    executor = Process('flow', user_name, cwd, cmd, args)
    print('starting ', cmd)
    await executor.start()

    done = aio.Event()
    # stdin_reader, stdout_writer = await get_standard_streams()
    loop = aio.get_running_loop()
    stdin_reader = aio.StreamReader()
    protocol = aio.StreamReaderProtocol(stdin_reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)

    # USE PTY

    async def feed_input():
        data = await stdin_reader.read(1000)
        # print(data)
        return data

    def print_output(output: bytes):
        sys.stdout.buffer.write(output)
        sys.stdout.flush()

    def notify_finish():
        print('finishing ', cmd)
        done.set()

    aio.create_task(executor.run(feed_input, print_output, notify_finish))
    await done.wait()


if __name__ == '__main__':
    aio.run(main())


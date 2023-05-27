import sys
import asyncio as aio
from ndsh.executor import Executor


async def main():
    my_args = sys.argv[1:]
    user_name, cwd, cmd = my_args[:3]
    args = my_args[3:]
    try:
        executor = Executor(user_name)
    except KeyError as e:
        print(f'Unable to obtain user: {e}')
        return
    print('starting ', cmd)
    await executor.run(cwd, cmd, args)


if __name__ == '__main__':
    aio.run(main())

# sudo poetry run python main.py root $(pwd) /bin/bash --norc

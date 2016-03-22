import asyncio
from aiozmq import rpc
import signal
import os

class Handler(rpc.AttrHandler):

    @rpc.method
    async def add(self, a: int, b: int) -> int:
        print('add %d, %d' % (a, b))
        await asyncio.sleep(3)
        print('finished sleeping')
        return a + b

    def hidden(self):
        return 'wtf'

def close(loop, server, signame):
    print('close(): got signal %s: closing' % signame)
    print('close(): closing server')
    server.close()
    print('close(): closing event loop')
    loop.stop()

async def run(loop, server_addr):
    print('rpc starting server...')
    server = await rpc.serve_rpc(
        Handler(),
        bind=server_addr,
        log_exceptions=True
    )

    for signame in ('SIGINT', 'SIGTERM'):
        loop.add_signal_handler(
            getattr(signal, signame),
            lambda: close(loop, server, signame)
        )

# server_addr = 'ipc://add_server.ipc'
server_addr = 'tcp://127.0.0.1:2205'
print('server running at "%s", pid: %s' % (server_addr, os.getpid()))

loop = asyncio.get_event_loop()
loop.create_task(run(loop, server_addr))

try:
    loop.run_forever()
finally:
    print('closing event loop')
    loop.close()

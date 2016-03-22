import asyncio
from aiozmq import rpc

# debugging:
# sudo tcpdump -i lo -f -X -S -s 0 'tcp port 2205'

async def run(server_addr):
    print('connecting to rpc server...')
    client = await rpc.connect_rpc(connect=server_addr, timeout=5)

    for i in range(10):
        res = await client.call.add(123, 456)
        print('add_server.add(4, 2) = %d' % res)
        await asyncio.sleep(3)

    print('closing client')
    client.close()
    await client.wait_closed()

# server_addr = 'ipc://add_server.ipc'
server_addr = 'tcp://127.0.0.1:2205'

loop = asyncio.get_event_loop()
loop.run_until_complete(run(server_addr))
print('closing event loop')
loop.close()

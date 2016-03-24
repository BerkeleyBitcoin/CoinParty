"""
Mixing Peer State and RPC Interface
"""

import asyncio
import aiozmq.rpc

class MixingPeer(rpc.AttrHandler):

    def __init__(self):
        self.addr = None
        self.peer_id = None # hash of public key? easier to use than index which needs to assigned and reassigned
        self.n_input_peers = 0
        self.input_peers = []
        self.n_mixing_peers = 0
        self.mixing_peers = []
        self.keypair = None

    async def committment(self):
        shares = self.c2_generate_random_shares()
        await self.c3_broadcast_public_shares(self, shares)
        self.wait_for_peer_shares()

    def c2_generate_random_shares(self):
        shares = [generate_share() for _ in input_peers]
        return shares

    async def c3_broadcast_public_shares(self, shares):
        coros = [mixing_peer.rpc.call.c3_push_public_shares(shares)
                 for mixing_peer in self.mixing_peers]
        results = await asyncio.gather(*coros, return_exceptions=True)
        for res in results:
            # validate peers received shares
            pass

    @rpc.method
    def request_start(self):
        pass

    @rpc.method
    def c3_push_public_shares(self, shares):
        pass

class RemoteMixingPeer:

    def __init__(self):
        self.addr = None
        self.public_key = None
        self.connection = None
        self.rpc = connection.rpc.call


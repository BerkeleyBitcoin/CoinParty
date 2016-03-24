"""
Input Peer State and RPC Interface
"""

from aiozmq import rpc

class InputPeer(rpc.AttrHandler):

    def __init__(self):
        self.addr = None

class RemoteInputPeer:

    def __init__(self):
        self.addr = None
        self.public_key = None
        self.connection = None
        self.rpc = connection.rpc.call


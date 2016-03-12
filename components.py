class State:

    def __init__(self):
        self.mixing_peers = []
        self.input_peers = []


class MixingPeer:

    def __init__(self, location, index):
        self.location = location
        self.index = index


class InputPeer:

    def __init__(self, location, index):
        self.location = location
        self.index = index

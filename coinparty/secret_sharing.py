import base64
import random  # TODO ensure that this is secure


class BaseScheme:
    """
    Provides an interface for secret sharing schemes, and Base64 encodes
    the initial secret
    """

    def __init__(self, secret, recovery_groups):
        self.secret = [secret].pack('m')
        self.secret_size = secret.unpack('B*').first.size
        self.recovery_groups = set(recovery_groups)

    def shares(self):
        self.shares = self.compute_shares()

    def recover_secret(*_shares):
        raise NotImplementedError()

    # NOTE: These instance variables should be read only:
    #           secret, secret_size, recovery_groups
    # NOTE: The following methods should be private

    def is_qualifying(self, group):
        for recovery_group in self.recovery_groups:
            if recovery_group in set(group):
                return True
        return False

    def binify_share(self, share):
        [share.to_s(2).rjust(self.secret_size, '0')].pack('B*')

    def generate_random_share(self):
        random.random_bytes(self.secret_size / 8).unpack('B*')[0].to_i(2)

    def parties(self):
        parties = reduce(lambda x, y: x + y, self.recovery_groups).freeze()
        return parties


# Replicated secret sharing scheme
class ReplicatedScheme(BaseScheme):

    def recover_secret(self, *shares):
        # NOTE: Whether the following XOR (^) needs to be bitwise or boolean is undetermined
        xor_binary = self.binify_share(reduce(lambda a, e: a ^ e, shares))
        if xor_binary == self.secret:
            base64.decode64(xor_binary)

    def maximally_non_qualifying(self):
        if not self.mnq:
            self.mnq = self.compute_maximally_non_qualifying.freeze()

    # NOTE: The following methods should be private

    def compute_maximally_non_qualifying(self, base_group=set()):
        next_non_qualifying = map(lambda party: base_group + [party], self.parties - base_group)

        next_non_qualifying = [group for group in next_non_qualifying if not self.is_qualifying(group)]

        if next_non_qualifying.empty:
            return [base_group]

        else:
            next_non_qualifying = map(lambda group: self.compute_maximally_non_qualifying(group), next_non_qualifying)
            return reduce(lambda x, y: x + y, next_non_qualifying)

    def compute_shares(self):
        shares = [self.generate_random_share() for _ in range(self.maximally_non_qualifying.size)]
        shares.pop() # remove last random
        shares << (reduce(lambda x, y: x ^ y, shares) ^ self.secret.unpack('B*').first.to_i(2))

        self.maximally_non_qualifying = zip(self.maximally_non_qualifying, shares)
        party_shares = {}
        for mnq, share in self.maximally_non_qualifying:
            b = self.parties - mnq

            def temp(party):
                party_shares[party] = [party_shares[party], share]
            reduce(temp, b)


# Informationally secure secret sharing device.
class ItoNishizekiSeitoScheme(BaseScheme):

    # Standard XOR of all shares to recover secret. Very much like a one-time pad.
    def recover_secret(self, *shares):
        xor_binary = self.binify_share(reduce(lambda a, e: a ^ e, shares))
        if xor_binary == self.secret:
            base64.decode64(xor_binary)

    # NOTE: The following methods should be private

    def compute_shares(self):
        for p in self.parties:
            self.parties[p] = [p, []]

        for group, shares in self.recovery_groups:
            random_shares = group.first(group.size - 1)
            random_shares = map(lambda _: self.generate_random_share(), random_shares)
            det_share = reduce(lambda a, e: a ^ e, self.secret.unpack('B*').first.to_i(2) + random_shares)

            group_shares = random_shares.concat([det_share])
            map(lambda share, party: shares[party].push(share), zip(group_shares, group))

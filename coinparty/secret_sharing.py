class BaseScheme:
    """
    Provides an interface for secret sharing schemes, and Base64 encodes
    the initial secret
    """

    def initialize(secret, recovery_groups):
        self.secret = [secret].pack('m')
        self.secret_size = secret.unpack('B*').first.size
        self.recovery_groups = set(recovery_groups)

    def shares():
        self.shares = self.compute_shares()

    def recover_secret(*_shares):
        raise NotImplementedException()

    # NOTE: These instance variables should be read only:
    #           secret, secret_size, recovery_groups
    # NOTE: The following methods should be private

    def is_qualifying(group):
        recovery_groups.any? { |recovery_group| recovery_group.subset?(Set.new(group)) }

    def binify_share(share):
        [share.to_s(2).rjust(secret_size, '0')].pack('B*')

    def generate_random_share:
        SecureRandom.random_bytes(secret_size / 8).unpack('B*')[0].to_i(2)

    def parties():
        parties = recovery_groups.inject(:+).freeze


require 'base64'
require 'securerandom'
require_relative './base_scheme'


# Replicated secret sharing scheme
class ReplicatedScheme(BaseScheme):
    def recover_secret(*shares):
        # NOTE: Whether the following XOR (^) needs to be bitwise or boolean is undetermined
        xor_binary = binify_share(reduce(lambda a, e: a ^ e, shares))
        if xor_binary == secret:
            Base64.decode64(xor_binary)

    def maximally_non_qualifying:
        if not self.mnq:
            self.mnq = compute_maximally_non_qualifying.freeze()

    # NOTE: The following methods should be private

    def compute_maximally_non_qualifying(base_group = Set.new):
        next_non_qualifying = map(lambdas party: base_group + [party], parties - base_group)

        next_non_qualifying = [group for group in next_non_qualifying if not is_qualifying(group)]

        if next_non_qualifying.empty:
            return [base_group]

        else:
            next_non_qualifying = map(lambda group: compute_maximally_non_qualifying(group), next_non_qualifying)
            return reduce(lambda x, y: x + y, next_non_qualifying, Set.new)

    def compute_shares:
        shares = [self.generate_random_share() for _ in range(maximally_non_qualifying.size)]
        shares.pop() # remove last random
        shares << (reduce(lambda x, y: x ^ y, shares) ^ secret.unpack('B*').first.to_i(2))

        maximally_non_qualifying = zip(maximally_non_qualifying, shares)
        party_shares = {}
        for mnq, share in maximally_non_qualifying:
            b = parties - mnq
            reduce(lambda party: party_shares[party] = [*party_shares[party], share], b)


require 'base64'
require 'securerandom'
require_relative './base_scheme'


# Informationally secure secret sharing device.
class ItoNishizekiSeitoScheme(BaseScheme):

    # Standard XOR of all shares to recover secret. Very much like a one-time pad.
    def recover_secret(*shares):
        xor_binary = binify_share(reduce(lambda a, e: a ^ e, shares))
        if xor_binary == secret:
            Base64.decode64(xor_binary)

    # NOTE: The following methods should be private

    def compute_shares():
        initial_shares = {}
        for p in parties:
            parties[p] = [p, []]

        for group, shares in recovery_groups:
            random_shares = group.first(group.size - 1)
            random_shares = map(lambda _: self.generate_random_share(), random_shares)
            det_share = reduce(lambda a, e: a ^ e, secret.unpack('B*').first.to_i(2) + random_shares)

            group_shares = random_shares.concat([det_share])
            map(lambda share, party: shares[party].push(share), zip(group_shares, group))

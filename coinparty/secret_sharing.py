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

    def parties:
        parties = recovery_groups.inject(:+).freeze


require 'base64'
require 'securerandom'
require_relative './base_scheme'


# Replicated secret sharing scheme
class ReplicatedScheme(BaseScheme):
    def recover_secret(*shares):
        xor_binary = binify_share(shares.flatten.reduce { |a, e| a ^ e })
        xor_binary == secret ? Base64.decode64(xor_binary) : nil

    def maximally_non_qualifying:
        mnq ||= compute_maximally_non_qualifying.freeze

    private

    def compute_maximally_non_qualifying(base_group = Set.new):
        next_non_qualifying = (parties - base_group).
            map { |party| base_group + [party] }.
            reject { |group| is_qualifying(group) }

        return [base_group] if next_non_qualifying.empty?

        next_non_qualifying.
            map { |group| compute_maximally_non_qualifying(group) }.
            inject(Set.new, :+)

    def compute_shares:
        shares = Array.new(maximally_non_qualifying.size) { generate_random_share }
        shares.pop # remove last random
        shares << (shares.inject(0, :^) ^ secret.unpack('B*').first.to_i(2))

        maximally_non_qualifying.zip(shares).
            each_with_object({}) do |(mnq, share), party_shares|
            b = parties - mnq
            b.each { |party| party_shares[party] = [*party_shares[party], share] }


require 'base64'
require 'securerandom'
require_relative './base_scheme'

# Informationally secure secret sharing device.
class ItoNishizekiSeitoScheme(BaseScheme):

    # Standard XOR of all shares to recover secret. Very much like a one-time pad.
    def recover_secret(*shares):
        xor_binary = binify_share(shares.reduce { |a, e| a ^ e })
        xor_binary == secret ? Base64.decode64(xor_binary) : nil

    private

    def compute_shares():
        initial_shares = Hash[parties.map { |p| [p, []] }]

        recovery_groups.each_with_object(initial_shares) do |group, shares|
            random_shares = group.first(group.size - 1).map { |_| generate_random_share }
            det_share = random_shares.
                reduce(secret.unpack('B*').first.to_i(2)) { |a, e| a ^ e }

            group_shares = random_shares.concat([det_share])
            group_shares.zip(group).each { |share, party| shares[party].push(share) }

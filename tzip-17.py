import smartpy as sp

permitKey = sp.TRecord(address=sp.TAddress, paramHash=sp.TBytes)
userStore = sp.TRecord(expiry=sp.TInt, counter=sp.TInt)


class TZIP17(sp.Contract):
    def __init__(self, _admin, _defaultExpiry):
        self.init(admin=_admin, active=sp.bool(True), default_expiry=_defaultExpiry, permits=sp.big_map(tkey=permitKey, tvalue=sp.TTimestamp),
                  user_store=sp.big_map(tkey=sp.TAddress, tvalue=userStore), permit_expires=sp.big_map(tkey=permitKey, tvalue=sp.TInt))

    def onlyByAdmin(self):
        sp.verify(sp.sender == self.data.admin)

    def contractIsActive(self):
        sp.verify(self.data.active == sp.bool(True))

    def initUserDefault(self, address):
        sp.if self.data.default_expiry < 0:
            self.data.default_expiry = 0

        sp.if self.data.user_store.contains(address) == sp.bool(False):
            self.data.user_store[address] = sp.record(
                expiry=self.data.default_expiry, counter=0)

    def getPermitExpiry(self, permit):
        defaultExp = self.data.user_store[permit.address].expiry
        return self.data.permit_expires.get(permit, defaultExp)

    def getAddressFromPubKey(self, pubKey):
        return sp.to_address(sp.implicit_account(sp.hash_key(pubKey)))

    @sp.entry_point
    def toggleContractState(self, params):
        self.onlyByAdmin()
        self.data.active = params._active

    @sp.entry_point
    def permit(self, params):
        address = self.getAddressFromPubKey(params.key)

        self.initUserDefault(address)

        rec = sp.record(address=address, paramHash=params.bytes)
        expTime = self.getPermitExpiry(rec)

        sp.verify(~(self.data.permits.contains(rec) & (
            self.data.permits[rec].add_seconds(expTime) > sp.now)), "DUP_PERMIT")

        data = sp.pack(sp.record(chain_id=sp.chain_id, contract_addr=sp.self_address,
                                 counter=self.data.user_store[address].counter, param_hash=params.bytes))

        sp.verify(sp.check_signature(
            params.key, params.signature, data), "MISSIGNED")

        self.data.permits[rec] = sp.now

        self.data.user_store[address].counter += 1

    @sp.entry_point
    def setUserExpiry(self, params):
        self.initUserDefault(sp.sender)
        sp.if params.seconds < 0:
            params.seconds = 0
        self.data.user_store[sp.sender].expiry = params.seconds

    @sp.entry_point
    def setPermitExpiry(self, params):
        self.initUserDefault(sp.sender)
        sp.if params.seconds < 0:
            params.seconds = 0
        rec = sp.record(address=sp.sender, paramHash=params.bytes)
        self.data.permit_expires[rec] = params.seconds


@sp.add_test(name="TZIP-17")
def test():
    alice = sp.test_account("Alice")
    bob = sp.test_account("Bob")

    c1 = TZIP17(_admin=bob.address, _defaultExpiry=10000)
    scenario = sp.test_scenario()
    scenario.table_of_contents()
    scenario.h1("TZIP-17")
    scenario += c1

    scenario.h2("Testing Permit")

    chainId = sp.chain_id_cst("0x9caecab9")

    # counter=0
    paramHash = sp.blake2b(sp.pack(42))
    data = sp.pack(sp.record(chain_id=chainId,
                             contract_addr=c1.address, counter=0, param_hash=paramHash))
    sig = sp.make_signature(alice.secret_key, data, message_format='Raw')

    # counter=1
    paramHash1 = sp.blake2b(sp.pack(43))
    data1 = sp.pack(sp.record(
        chain_id=chainId, contract_addr=c1.address, counter=1, param_hash=paramHash1))
    sig1 = sp.make_signature(alice.secret_key, data1, message_format='Raw')

    # anyone can send the permit
    scenario += c1.permit(key=alice.public_key, signature=sig, bytes=paramHash).run(
        sender=bob, chain_id=chainId, now=sp.timestamp("15665656"))

    # but the pubKey should match, throws MISSIGNED err
    scenario += c1.permit(key=bob.public_key, signature=sig, bytes=paramHash).run(
        sender=bob, chain_id=chainId, now=sp.timestamp("15665656"), valid=False)

    # same permit cannot be sent again, throws DUP_PERMIT err [previous permit is still valid]
    scenario += c1.permit(key=alice.public_key, signature=sig, bytes=paramHash).run(
        sender=bob, chain_id=chainId, now=sp.timestamp("15665656"), valid=False)

    # same permit cannot be sent again, throws MISSIGNED err [counter wrong]
    scenario += c1.permit(key=alice.public_key, signature=sig, bytes=paramHash).run(
        sender=bob, chain_id=chainId, now=sp.timestamp("15685656"), valid=False)

    scenario.h2("Testing SetEpiry")

    # expiry time for permit can be changed [set user default]
    scenario += c1.setUserExpiry(seconds=0).run(sender=alice)

    # permit is immediately expired as user default set to 0, should throw MISSIGNED err and not DUP_PERMIT
    scenario += c1.permit(key=alice.public_key, signature=sig, bytes=paramHash).run(
        sender=bob, chain_id=chainId, now=sp.timestamp("15665656"), valid=False)

    # new permit with counter=1 from alice
    scenario += c1.permit(key=alice.public_key, signature=sig1, bytes=paramHash1).run(
        sender=bob, chain_id=chainId, now=sp.timestamp("15665656"))

    # set specific param exp
    scenario += c1.setPermitExpiry(seconds=10000,
                                   bytes=paramHash1).run(sender=alice)

    # permit is not expired even though user default is 0, should throw DUP_PERMIT not MISSIGNED err
    scenario += c1.permit(key=alice.public_key, signature=sig1, bytes=paramHash1).run(
        sender=bob, chain_id=chainId, now=sp.timestamp("15665656"), valid=False)

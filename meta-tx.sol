import smartpy as sp

# Type aliases
blake2b_hash = sp.TBytes
seconds = sp.TNat

permitKey = sp.TRecord(address=sp.TAddress, param_hash=blake2b_hash)
userStore = sp.TRecord(expiry=sp.TOption(seconds), counter=sp.TInt)

permit_parameters_type = sp.TRecord(key=sp.TKey, signature=sp.TSignature, param_hash=blake2b_hash)


# MetaTransaction is a contract that implements native meta transactions
# along the guidelines of TZIP-17.
class MetaTransaction(sp.Contract):
    def __init__(self, default_expiry = 10, **kargs):
        self.init(
            default_expiry=default_expiry,
            permits=sp.big_map(tkey=permitKey, tvalue=sp.TTimestamp),
            user_store=sp.big_map(tkey=sp.TAddress, tvalue=userStore),
            permit_expiries=sp.big_map(tkey=permitKey, tvalue=sp.TOption(seconds)), **kargs
        )

    def get_counter(self, address):
        counter=sp.local("counter",0)
        sp.if self.data.user_store.contains(address):
            counter.value=self.data.user_store[address].counter
        return counter.value
        
    def increment_counter(self, address):
        sp.if ~self.data.user_store.contains(address):
            self.data.user_store[address] = sp.record(
                expiry=sp.none,
                counter=0
            )
        self.data.user_store[address].counter += 1
        
    def get_user_expiry(self, address):
        user_expiry=sp.local("user_expiry",self.data.default_expiry)
        sp.if self.data.user_store.contains(address):
            sp.if self.data.user_store[address].expiry.is_some():
                user_expiry.value=self.data.user_store[address].expiry.open_some()
        return user_expiry.value
    
    def assert_permit_exists(self, address, param_hash):
        rec = sp.record(address=address, param_hash=param_hash)
        sp.verify(
            self.data.permits.contains(rec),
            "Permit does not exist"
        )

    def assert_permit_not_expired(self, address, param_hash):
        rec = sp.record(address=address, param_hash=param_hash)
        permit_created_at = self.data.permits[rec]
        
        user_expiry=self.get_user_expiry(address)
        permit_expires_in=sp.local("permit_expires_in",user_expiry)
        sp.if self.data.permit_expiries.contains(rec):
            sp.if self.data.permit_expiries[rec].is_some():
                permit_expires_in.value=self.data.permit_expiries[rec].open_some()
        permit_expires_at = permit_created_at.add_seconds(sp.to_int(permit_expires_in.value))
        did_expire = permit_expires_at < sp.now
        sp.verify(~did_expire, "PERMIT_EXPIRED")

    def get_address_from_pub_key(self, pub_key):
        return sp.to_address(sp.implicit_account(sp.hash_key(pub_key)))

    def handle_meta_tx(self, key, signature, param_hash):
        address = self.get_address_from_pub_key(key)
        counter = self.get_counter(address)
        data = sp.pack(
            sp.record(
                chain_id=sp.chain_id,
                contract_addr=sp.self_address,
                counter=counter,
                param_hash=param_hash
            )
        )
        sp.verify(
            sp.check_signature(key, signature, data),
            "MISSIGNED"
        )
        self.increment_counter(address)
        
    @sp.entry_point
    def permit(self, key, signature, param_hash):
        address = self.get_address_from_pub_key(key)
        
        rec = sp.record(address=address, param_hash=param_hash)
        sp.verify(~(self.data.permits.contains(rec)), "DUP_PERMIT")

        self.handle_meta_tx(key, signature, param_hash)
        
        self.data.permits[rec] = sp.now

    @sp.entry_point
    def set_user_expiry(self, user_default_expiry):
        sp.if ~self.data.user_store.contains(sp.sender):
            self.data.user_store[sp.sender] = sp.record(
                expiry=sp.some(user_default_expiry),
                counter=0
            )
        sp.else:
            self.data.user_store[sp.sender].expiry = sp.some(user_default_expiry)

    @sp.entry_point
    def set_permit_expiry(self, param_hash, expires_in):
        self.assert_permit_exists(sp.sender, param_hash)
        rec = sp.record(address=sp.sender, param_hash=param_hash)
        self.data.permit_expiries[rec] = sp.some(expires_in)

# Sample DApp contract
class Quote(MetaTransaction):
  def __init__(self, _defaultExpiry):
      super().__init__(default_expiry = _defaultExpiry, quote=0)
      
  @sp.entry_point
  def set_quote(self, key, signature, new_quote):
      param_hash = sp.blake2b(sp.pack(new_quote))
      self.handle_meta_tx(key, signature, param_hash)
      self.data.quote = new_quote

@sp.add_test(name="MetaTransaction")
def test():
    alice = sp.test_account("Alice")
    bob = sp.test_account("Bob")

    c1 = Quote(_defaultExpiry=10000)
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
    scenario.h3("Bob sends a valid permit on behalf of Alice")
    scenario += c1.permit(key=alice.public_key, signature=sig, param_hash=paramHash).run(
        sender=bob, chain_id=chainId, now=sp.timestamp("15665656"))

    # but the pubKey should match, throws MISSIGNED err
    scenario.h3("Bob sends a invalid permit on behalf of Alice, pubKey mismatch")
    scenario += c1.permit(key=bob.public_key, signature=sig, param_hash=paramHash).run(
        sender=bob, chain_id=chainId, now=sp.timestamp("15665656"), valid=False)

    # same permit cannot be sent again, throws DUP_PERMIT err [previous permit is still valid]
    scenario.h3("Bob sends a same permit again on behalf of Alice, replay attack")
    scenario += c1.permit(key=alice.public_key, signature=sig, param_hash=paramHash).run(
        sender=bob, chain_id=chainId, now=sp.timestamp("15665656"), valid=False)

    # same permit cannot be sent again, throws MISSIGNED err [counter wrong]
    scenario += c1.permit(key=alice.public_key, signature=sig, param_hash=paramHash).run(
        sender=bob, chain_id=chainId, now=sp.timestamp("15685656"), valid=False)

    scenario.h2("Testing Set Expiry")

    # expiry time for permit can be changed [set user default]
    scenario.h3("Setting Alice's default expiry")
    scenario += c1.set_user_expiry(0).run(sender=alice)

    # new permit with counter=1 from alice
    scenario.h3("New Permit From Alice")
    scenario += c1.permit(key=alice.public_key, signature=sig1, param_hash=paramHash1).run(
        sender=bob, chain_id=chainId, now=sp.timestamp("15665656"))

    # set specific param exp
    scenario.h3("Setting expiry for the specific permit")
    scenario += c1.set_permit_expiry(expires_in=10000,
                                   param_hash=paramHash1).run(sender=alice)
        
    scenario.h2("Testing Sample Dapp")
    
    quote_value = 243
    paramHash = sp.blake2b(sp.pack(quote_value))

    data = sp.pack(sp.record(chain_id=chainId,
                             contract_addr=c1.address, counter=2, param_hash=paramHash))
    sig = sp.make_signature(alice.secret_key, data, message_format='Raw')
    
    scenario.h3("Bob sends a Quote on behalf of Alice")
    scenario += c1.set_quote(new_quote=quote_value, key=alice.public_key, signature=sig).run(
        sender=bob, chain_id=chainId, now=sp.timestamp("15665656"))
    
    # replay attack
    scenario.h3("Bob sends the Quote he sent previously on behalf of Alice")
    scenario += c1.set_quote(new_quote=quote_value, key=alice.public_key, signature=sig).run(
        sender=bob, chain_id=chainId, now=sp.timestamp("15665656"), valid=False)

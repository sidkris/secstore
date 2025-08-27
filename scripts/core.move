module secstore::vault {
    use std::signer;
    use std::string;
    use std::vector;
    use std::option;

    /// Each account owns exactly one SecureStore
    struct SecureStore has key {
        entries: vector<(string::String, vector<u8>)> // key → encrypted blob
    }

    /// Initialize store for the account
    public entry fun init(account: &signer) {
        move_to(account, SecureStore { entries: vector::empty() });
    }

    /// Put encrypted data
    public entry fun put(account: &signer, key: string::String, value: vector<u8>) acquires SecureStore {
        let store = borrow_global_mut<SecureStore>(signer::address_of(account));
        vector::push_back(&mut store.entries, (key, value));
    }

    /// Get encrypted data
    public fun get(account_addr: address, key: string::String): option::Option<vector<u8>> acquires SecureStore {
        let store = borrow_global<SecureStore>(account_addr);
        let mut i = 0;
        while (i < vector::length(&store.entries)) {
            let (k, v) = *vector::borrow(&store.entries, i);
            if (k == key) return option::some(v);
            i = i + 1;
        };
        option::none<vector<u8>>()
    }

    /// Delete entry
    public entry fun delete(account: &signer, key: string::String) acquires SecureStore {
        let store = borrow_global_mut<SecureStore>(signer::address_of(account));
        let mut i = 0;
        while (i < vector::length(&store.entries)) {
            let (k, _) = *vector::borrow(&store.entries, i);
            if (k == key) {
                vector::remove(&mut store.entries, i);
                return;
            };
            i = i + 1;
        };
    }
}

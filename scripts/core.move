module secstore::vault {
    use std::signer;
    use std::string;
    use std::vector;
    use std::option;

    /// Each entry is a key-value pair
    struct Entry has copy, drop, store {
        key: string::String,
        value: vector<u8>,
    }

    /// Each account owns exactly one SecureStore
    struct SecureStore has key {
        entries: vector<Entry>
    }

    /// Initialize store for the account
    public entry fun init(account: &signer) {
        move_to(account, SecureStore { entries: vector::empty<Entry>() });
    }

    /// Put encrypted data
    public entry fun put(account: &signer, key: string::String, value: vector<u8>) acquires SecureStore {
        let store = borrow_global_mut<SecureStore>(signer::address_of(account));
        let entry = Entry { key, value };
        vector::push_back(&mut store.entries, entry);
    }

    /// Get encrypted data
    public fun get(account_addr: address, key: string::String): option::Option<vector<u8>> acquires SecureStore {
        let store = borrow_global<SecureStore>(account_addr);
        let i = 0;
        while (i < vector::length(&store.entries)) {
            let entry_ref = vector::borrow(&store.entries, i);
            if (entry_ref.key == key) {
                return option::some(entry_ref.value);
            };
            let i = i + 1;
        };
        option::none<vector<u8>>()
    }

    /// Delete entry
    public entry fun delete(account: &signer, key: string::String) acquires SecureStore {
        let store = borrow_global_mut<SecureStore>(signer::address_of(account));
        let i = 0;
        while (i < vector::length(&store.entries)) {
            let entry_ref = vector::borrow(&store.entries, i);
            if (entry_ref.key == key) {
                vector::remove(&mut store.entries, i);
                return;
            };
            let i = i + 1;
        };
    }
}
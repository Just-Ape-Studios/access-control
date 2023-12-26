use ink::{primitives::AccountId, storage::Mapping};

#[derive(Debug, Default)]
#[ink::storage_item]
pub struct AccessControlData {
    /// An association between an account_id and the roles it has
    /// assigned.
    ///
    /// The roles are stored in a bitmap where each bit of an u128
    /// acts as a role. If that bit is 1 the role is set, otherwise
    /// it's unset.
    ///
    /// TODO (netfox)
    ///   consider making the roles a const generic slice of u8s.
    ///   That way the limit of 128 roles would disappear (tho you'd
    ///   need to worry not to store more than 16KiB of data), and the
    ///   memory footprint for contracts that only need a few roles
    ///   would be reduced.
    ///
    ///   Emulating a nested map like the following using slices
    ///   should(???) work: mapping(account_id, mapping(idx, roles))
    pub roles_per_account: Mapping<AccountId, u128>,
}

#[repr(transparent)]
#[derive(Debug, Copy, Clone, Default)]
pub struct BitMap(pub u128);

impl BitMap {
    #[inline]
    /// set_bit changes `bit` to 1
    pub fn set_bit(&mut self, bit: u8) -> &mut Self {
        self.0 |= 1u128 << bit;
        self
    }

    #[inline]
    /// clear_bit changes `bit` to 0
    pub fn clear_bit(&mut self, bit: u8) -> &mut Self {
        self.0 &= !(1u128 << bit);
        self
    }

    #[inline]
    /// has_bit_set returns true if `bit` is 1, false otherwise
    pub fn has_bit_set(&self, bit: u8) -> bool {
        (self.0 & (1 << bit)) > 0
    }
}

impl AccessControlData {
    pub fn set_role(&mut self, account_id: AccountId, role: u8) {
        assert!(role <= 127, "can only define up to 128 roles");

        let account_roles = self
            .roles_per_account
            .get(account_id)
            .map_or(*BitMap(0).set_bit(role), |roles| {
                *BitMap(roles).set_bit(role)
            });

        self.roles_per_account.insert(account_id, &account_roles.0);
    }

    pub fn unset_role(&mut self, account_id: AccountId, role: u8) {
        assert!(role <= 127, "can only define up to 128 roles");

        let account_roles = self
            .roles_per_account
            .get(account_id)
            .map_or(BitMap(0), |roles| *BitMap(roles).clear_bit(role));

        self.roles_per_account.insert(account_id, &account_roles.0);
    }

    pub fn has_role(&self, account_id: AccountId, role: u8) -> bool {
        assert!(role <= 127, "can only define up to 128 roles");

        match self.roles_per_account.get(account_id) {
            Some(curr_roles) => BitMap(curr_roles).has_bit_set(role),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitmap_set_bit() {
        let mut bm = BitMap(0);

        bm.set_bit(0).set_bit(1).set_bit(127);

        assert_eq!(bm.0, (1 << 127) + 2 + 1);
    }

    #[test]
    fn test_bitmap_clear_bit() {
        let mut bm = BitMap(u128::MAX);

        bm.clear_bit(0).clear_bit(1).clear_bit(127);

        assert_eq!(bm.0, u128::MAX - (1 << 127) - 2 - 1);
    }

    #[test]
    fn test_bitmap_has_bit_set() {
        let bm = BitMap(0b1101u128);

        assert_eq!(bm.has_bit_set(0), true);
        assert_eq!(bm.has_bit_set(1), false);
        assert_eq!(bm.has_bit_set(2), true);
        assert_eq!(bm.has_bit_set(3), true);
    }

    #[ink::test]
    fn set_role_works() {
        let mut access_control = AccessControlData::default();
        let account = AccountId::from([1u8; 32]);
	let (r1, r2) = (0, 1);

	// set some roles and check that they have been set
        access_control.set_role(account, r1);
        access_control.set_role(account, r2);

        let roles = access_control
            .roles_per_account
            .get(account)
            .unwrap_or_else(|| panic!());

        assert_eq!(roles, 3);
    }

    #[ink::test]
    fn unset_role_works() {
        let mut access_control = AccessControlData::default();
        let account = AccountId::from([1u8; 32]);
	let (r1, r2, r3, r4) = (0, 1, 2, 8);

	// set some roles for testing
        access_control.set_role(account, r1);
        access_control.set_role(account, r2);
        access_control.set_role(account, r3);

	// unset one of the roles and check that it has been unset
	access_control.unset_role(account, r2);

	// verify that unset'ing a role that is not set doesn't do
	// anything weird
	access_control.unset_role(account, r4);

        let roles = access_control
            .roles_per_account
            .get(account)
            .unwrap_or_else(|| panic!());

        assert_eq!(roles, 5);
    }

    #[ink::test]
    fn has_role_works() {
        let mut access_control = AccessControlData::default();
        let account = AccountId::from([1u8; 32]);
	let (r1, r2, r3, r4, r5) = (0, 1, 2, 3, 4);

	// set some roles for testing
        access_control.set_role(account, r1);
        access_control.set_role(account, r2);
        access_control.set_role(account, r5);

	assert_eq!(access_control.has_role(account, r1), true);
	assert_eq!(access_control.has_role(account, r2), true);
	assert_eq!(access_control.has_role(account, r3), false);
	assert_eq!(access_control.has_role(account, r4), false);
	assert_eq!(access_control.has_role(account, r5), true);
    }
}

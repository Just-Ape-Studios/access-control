use ink::{prelude::vec, prelude::vec::Vec, primitives::AccountId, storage::Mapping};

#[derive(Default)]
#[ink::storage_item]
pub struct RolesData {
    /// An association between an account_id and the roles it has
    /// assigned.
    ///
    /// The roles are stored in a bitmap where each bit of an u128
    /// acts as a role. If that bit is 1 the role is set, otherwise
    /// it's unset.
    roles_per_account: Mapping<AccountId, BitMap>,
}

#[repr(transparent)]
#[derive(Debug, Copy, Clone, Default, scale::Encode, scale::Decode)]
#[cfg_attr(
    feature = "std",
    derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
)]
struct BitMap(pub u128);

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

pub trait Internal {
    /// set_role grants a `role` to an `account_id`.
    fn set_role(&mut self, account_id: AccountId, role: u8);

    /// unset_role denies an assigned `role` from an `account_id`.
    fn unset_role(&mut self, account_id: AccountId, role: u8);

    /// has_role returns true if `account_id` has `role` assigned,
    /// false otherwise
    fn has_role(&self, account_id: AccountId, role: u8) -> bool;

    /// get_roles_of returns all the roles that `account_id` has assigned
    fn get_roles_of(&self, account_id: AccountId) -> Vec<u8>;
}

impl Internal for RolesData {
    fn set_role(&mut self, account_id: AccountId, role: u8) {
        assert!(role <= 127, "can only define up to 128 roles");

        let account_roles = self
            .roles_per_account
            .get(account_id)
            .map_or(BitMap(0), |roles| *roles.clone().set_bit(role));

        self.roles_per_account.insert(account_id, &account_roles);
    }

    fn unset_role(&mut self, account_id: AccountId, role: u8) {
        assert!(role <= 127, "can only define up to 128 roles");

        let account_roles = self
            .roles_per_account
            .get(account_id)
            .map_or(BitMap(0), |roles| *roles.clone().clear_bit(role));

        self.roles_per_account.insert(account_id, &account_roles);
    }

    fn has_role(&self, account_id: AccountId, role: u8) -> bool {
        assert!(role <= 127, "can only define up to 128 roles");

        match self.roles_per_account.get(account_id) {
            Some(curr_roles) => curr_roles.has_bit_set(role),
            None => false,
        }
    }

    fn get_roles_of(&self, account_id: AccountId) -> Vec<u8> {
        match self.roles_per_account.get(account_id) {
            Some(curr_roles) => (0..=127)
                .filter(|role| curr_roles.has_bit_set(*role))
                .collect(),
            None => vec![],
        }
    }
}

#[ink::trait_definition]
pub trait AccessControl {
    #[ink(message)]
    fn set_role(&mut self, account_id: AccountId);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitmap_set_bit() {
	let mut bm = BitMap(0);

	bm.set_bit(0)
          .set_bit(1)
	  .set_bit(127);

	assert_eq!(bm.0, (1 << 127) + 2 + 1);
    }

    #[test]
    fn test_bitmap_clear_bit() {
	let mut bm = BitMap(u128::MAX);

	bm.clear_bit(0)
          .clear_bit(1)
	  .clear_bit(127);

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
}

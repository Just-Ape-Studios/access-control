use ink::{prelude::vec, prelude::vec::Vec, primitives::AccountId, storage::Mapping};

/// AccessControlData encapsulates the process of assigning roles
/// to accounts and verifying them.
///
/// The generic const `N` represents the static size in bytes of the
/// inner vector that will be used to store the roles associated with
/// each account. Each byte is able to store 8 roles.
///
/// E.g. AccessControlData<4> allocates inner vectors of 4 bytes,
/// which will be able to store 8 * 4 = 32 roles
#[derive(Debug)]
#[ink::storage_item]
pub struct AccessControlData<const N: usize> {
    /// An association between an account_id and the roles it has
    /// assigned. Only serves the purpose of checking whenever the
    /// account has the role, but doesn't give authorization to that
    /// account to set the role for other accounts
    pub roles_per_account: Mapping<AccountId, BitMap>,

    pub admin_roles_per_account: Mapping<AccountId, BitMap>,
}

#[repr(transparent)]
#[derive(Debug, Clone, scale::Encode, scale::Decode)]
#[cfg_attr(
    feature = "std",
    derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
)]
// NOTE:
//
// Once we switch to ink! 5 we'll be able to replace the vector
// with a const generic slice. The issue is that StorageLayout
// is not implemented for [T; N] until ink! 5. Tried to implement
// it manually but couldn't get past the issues with std.
//
// Related info:
// - https://github.com/paritytech/ink/pull/1787
// - https://github.com/paritytech/ink/issues/1785
pub struct BitMap(Vec<u8>);

impl BitMap {
    pub fn new(sz: usize) -> Self {
        BitMap(vec![0u8; sz])
    }

    #[inline]
    /// set_bit changes the bit at `pos` to 1
    pub fn set_bit(&mut self, pos: usize) -> &mut Self {
        let idx = pos / 8;
        let off = pos % 8;
        self.0[idx] |= 1u8 << off;
        self
    }

    #[inline]
    /// clear_bit changes the bit at `pos` to 0
    pub fn clear_bit(&mut self, pos: usize) -> &mut Self {
        let idx = pos / 8;
        let off = pos % 8;
        self.0[idx] &= !(1u8 << off);
        self
    }

    #[inline]
    /// has_bit_set returns true if the bit at `pos` is 1, false otherwise
    pub fn has_bit_set(&self, pos: usize) -> bool {
        let idx = pos / 8;
        let off = pos % 8;
        (self.0[idx] & (1 << off)) > 0
    }
}

#[derive(Debug)]
pub enum AccessControlError {
    CallerIsNotAdmin,
}

impl<const N: usize> AccessControlData<N> {
    const DEFAULT_ADMIN_ROLE: usize = 0;

    pub fn new(admin: AccountId) -> Self {
        const {
            assert!(N <= 32, "N generic const can't be greater than 32");
        }

        let mut roles_bm = BitMap::new(N);
        roles_bm.set_bit(Self::DEFAULT_ADMIN_ROLE);

        let mut admin_roles = Mapping::new();
        admin_roles.insert(admin, &roles_bm);

        AccessControlData {
            roles_per_account:       Mapping::new(),
            admin_roles_per_account: admin_roles,
        }
    }

    pub fn set_role(
        &mut self,
        caller: AccountId,
        account_id: AccountId,
        role: usize,
    ) -> Result<(), AccessControlError> {
        assert!(role > 0, "role id must be greater than 0");

        if !self.has_admin_role(caller, role)
            && !self.has_admin_role(caller, Self::DEFAULT_ADMIN_ROLE)
        {
            return Err(AccessControlError::CallerIsNotAdmin);
        }

        let account_roles = self.roles_per_account.get(account_id).map_or_else(
            || {
                let mut bm = BitMap::new(N);
                bm.set_bit(role);
                bm
            },
            |roles| {
                let mut bm = roles.clone();
                bm.set_bit(role);
                bm
            },
        );

        self.roles_per_account.insert(account_id, &account_roles);
        Ok(())
    }

    pub fn unset_role(
        &mut self,
        caller: AccountId,
        account_id: AccountId,
        role: usize,
    ) -> Result<(), AccessControlError> {
        assert!(role > 0, "role id must be greater than 0");

        if !self.has_admin_role(caller, role)
            && !self.has_admin_role(caller, Self::DEFAULT_ADMIN_ROLE)
        {
            return Err(AccessControlError::CallerIsNotAdmin);
        }

        let account_roles =
            self.roles_per_account
                .get(account_id)
                .map_or(BitMap::new(N), |roles| {
                    let mut bm = roles.clone();
                    bm.clear_bit(role);
                    bm
                });

        self.roles_per_account.insert(account_id, &account_roles);
        Ok(())
    }

    pub fn has_role(&self, account_id: AccountId, role: usize) -> bool {
        match self.roles_per_account.get(account_id) {
            Some(curr_roles) => curr_roles.has_bit_set(role),
            None => false,
        }
    }

    pub fn has_admin_role(&self, account_id: AccountId, role: usize) -> bool {
        match self.admin_roles_per_account.get(account_id) {
            Some(curr_roles) => curr_roles.has_bit_set(role),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitmap_set_bit() {
        let mut bm = BitMap([0u8; 4].into());

        bm.set_bit(0).set_bit(1).set_bit(31);

        assert_eq!(bm.0[0], 3);
        assert_eq!(bm.0[1], 0);
        assert_eq!(bm.0[2], 0);
        assert_eq!(bm.0[3], 128);
    }

    #[test]
    fn test_bitmap_clear_bit() {
        let mut bm = BitMap([u8::MAX; 4].into());

        bm.clear_bit(0).clear_bit(1).clear_bit(31);

        assert_eq!(bm.0[0], u8::MAX - 2 - 1);
        assert_eq!(bm.0[1], u8::MAX);
        assert_eq!(bm.0[2], u8::MAX);
        assert_eq!(bm.0[3], 127);
    }

    #[test]
    fn test_bitmap_has_bit_set() {
        let bm = BitMap([6, 2, 0, 0].into());

        assert_eq!(bm.has_bit_set(0), false);
        assert_eq!(bm.has_bit_set(1), true);
        assert_eq!(bm.has_bit_set(2), true);
        assert_eq!(bm.has_bit_set(9), true);
    }

    #[ink::test]
    fn set_role_works() {
        let caller = AccountId::from([0u8; 32]);
        let account = AccountId::from([1u8; 32]);
        let mut access_control = AccessControlData::<4>::new(caller);
        let (r1, r2) = (1, 2);

        // set some roles and check that they have been set
        access_control.set_role(caller, account, r1).unwrap();
        access_control.set_role(caller, account, r2).unwrap();

        let roles = access_control
            .roles_per_account
            .get(account)
            .unwrap_or_else(|| panic!());

        assert_eq!(roles.0, [6, 0, 0, 0]);
    }

    #[ink::test]
    fn unset_role_works() {
        let caller = AccountId::from([0u8; 32]);
        let account = AccountId::from([1u8; 32]);
        let mut access_control = AccessControlData::<4>::new(caller);
        let (r1, r2, r3, r4) = (1, 2, 3, 8);

        // set some roles for testing
        access_control.set_role(caller, account, r1).unwrap();
        access_control.set_role(caller, account, r2).unwrap();
        access_control.set_role(caller, account, r3).unwrap();

        // unset one of the roles and check that it has been unset
        access_control.unset_role(caller, account, r2).unwrap();

        // verify that unset'ing a role that is not set doesn't do
        // anything weird
        access_control.unset_role(caller, account, r4).unwrap();

        let roles = access_control
            .roles_per_account
            .get(account)
            .unwrap_or_else(|| panic!());

        assert_eq!(roles.0, [10, 0, 0, 0]);
    }

    #[ink::test]
    fn has_role_works() {
        let caller = AccountId::from([0u8; 32]);
        let account = AccountId::from([1u8; 32]);
        let mut access_control = AccessControlData::<4>::new(caller);
        let (r1, r2, r3, r4, r5) = (1, 2, 3, 4, 5);

        // set some roles for testing
        access_control.set_role(caller, account, r1).unwrap();
        access_control.set_role(caller, account, r2).unwrap();
        access_control.set_role(caller, account, r5).unwrap();

        assert_eq!(access_control.has_role(account, r1), true);
        assert_eq!(access_control.has_role(account, r2), true);
        assert_eq!(access_control.has_role(account, r3), false);
        assert_eq!(access_control.has_role(account, r4), false);
        assert_eq!(access_control.has_role(account, r5), true);
    }
}

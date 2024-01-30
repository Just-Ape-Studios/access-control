#![cfg_attr(not(feature = "std"), no_std, no_main)]
#![feature(inline_const)]

mod internal;
pub use internal::AccessControlData;

use ink::primitives::AccountId;
use internal::{AccessControlError, Role};

#[ink::trait_definition]
pub trait AccessControl {
    #[ink(message)]
    fn grant_role(&mut self, account_id: AccountId, role: Role) -> Result<(), AccessControlError>;

    #[ink(message)]
    fn revoke_role(&mut self, account_id: AccountId, role: Role) -> Result<(), AccessControlError>;

    #[ink(message)]
    fn renounce_role(
        &mut self,
        account_id: AccountId,
        role: Role,
    ) -> Result<(), AccessControlError>;

    #[ink(message)]
    fn has_role(&mut self, account_id: AccountId) -> bool;
}

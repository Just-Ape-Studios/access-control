#![cfg_attr(not(feature = "std"), no_std, no_main)]
#![feature(inline_const)]

mod internal;
pub use internal::AccessControlData;

use ink::primitives::AccountId;

#[ink::trait_definition]
pub trait AccessControl {
    #[ink(message)]
    fn grant_role(&mut self, account_id: AccountId);

    #[ink(message)]
    fn revoke_role(&mut self, account_id: AccountId);
}

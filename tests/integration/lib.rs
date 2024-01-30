#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod integration {
    use access_control::{AccessControlData, Role};

    #[ink(storage)]
    pub struct Integration {
        access_control: AccessControlData<4>,
        value:          bool,
    }

    impl Integration {
        const ROLE_1: Role = 1;

        #[ink(constructor)]
        pub fn new(value: bool) -> Self {
            let caller = Self::env().caller();
            let mut access_control = AccessControlData::<4>::new(caller);

            if let Err(e) = access_control.set_role(caller, caller, Self::ROLE_1) {
                panic!("{:?}", e);
            }

            Self {
                value,
                access_control,
            }
        }

        #[ink(message)]
        pub fn flip(&mut self) {
            self.value = !self.value;
        }

        #[ink(message)]
        pub fn privileged_flip(&mut self) -> Result<(), ()> {
            let caller = self.env().caller();

            if !self.access_control.has_role(caller, Self::ROLE_1) {
                return Err(());
            }

            self.value = !self.value;
            Ok(())
        }

        #[ink(message)]
        pub fn get(&self) -> bool {
            self.value
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn flip_works() {
            let mut contract = Integration::new(false);
            assert_eq!(contract.get(), false);

            contract.flip();
            assert_eq!(contract.get(), true);
        }

        #[ink::test]
        fn privileged_flip_on_granted_account_works() {
            let mut contract = Integration::new(false);
            assert_eq!(contract.get(), false);

            let res = contract.privileged_flip();

            assert!(res.is_ok());
            assert_eq!(contract.get(), true);
        }

        #[ink::test]
        fn privileged_flip_on_non_granted_account_fails() {
            let mut contract = Integration::new(false);
            assert_eq!(contract.get(), false);

            // set the call to the contract to be done by the account bob,
            // who has no roles granted
            let accounts = ink::env::test::default_accounts::<ink::env::DefaultEnvironment>();

            let contract_id = ink::env::account_id::<ink::env::DefaultEnvironment>();
            ink::env::test::set_callee::<ink::env::DefaultEnvironment>(contract_id);
            ink::env::test::set_caller::<ink::env::DefaultEnvironment>(accounts.bob);

            let res = contract.privileged_flip();

            assert!(res.is_err());
            assert_eq!(contract.get(), false);
        }
    }
}

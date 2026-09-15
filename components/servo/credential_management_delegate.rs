/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */
use std::cell::RefCell;
use std::collections::HashMap;

use servo_url::ImmutableOrigin;

pub trait CredentialManagementDelegate {
    /// Stores a secret associated with the given key.
    /// The secret does not have to be a string.
    fn store_secret(&self, key: ImmutableOrigin, secret: Vec<u8>) -> Result<(), String>;
    /// - `Ok(None)` if the secret does not exist
    /// - `Ok(Some(secret))` if the secret exists
    /// - `Err` if there was an error retrieving the secret
    fn retrieve_secret(&self, key: ImmutableOrigin) -> Result<Option<Vec<u8>>, String>;
    /// Deletes the secret associated with the given key.
    /// If the secret does not exist, this should still be treated as a success.
    /// This should only return `Err` if there was an error during deletion.
    fn delete_secret(&self, key: ImmutableOrigin) -> Result<(), String>;
}

#[derive(Default)]
pub struct DefaultCredentialManagementDelegate {
    secrets: RefCell<HashMap<ImmutableOrigin, Vec<u8>>>,
}

impl CredentialManagementDelegate for DefaultCredentialManagementDelegate {
    fn store_secret(&self, key: ImmutableOrigin, secret: Vec<u8>) -> Result<(), String> {
        self.secrets.borrow_mut().insert(key, secret);
        Ok(())
    }

    fn retrieve_secret(&self, key: ImmutableOrigin) -> Result<Option<Vec<u8>>, String> {
        Ok(self.secrets.borrow().get(&key).cloned())
    }

    fn delete_secret(&self, key: ImmutableOrigin) -> Result<(), String> {
        self.secrets.borrow_mut().remove(&key);
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use servo_url::ServoUrl;

    fn origin(url: &str) -> ImmutableOrigin {
        ServoUrl::parse(url).unwrap().origin()
    }

    #[test]
    fn store_retrieve_delete_secret() {
        let delegate = DefaultCredentialManagementDelegate::default();
        let key = origin("https://example.com");
        let secret = b"secret".to_vec();

        assert_eq!(delegate.retrieve_secret(key.clone()).unwrap(), None);

        delegate
            .store_secret(key.clone(), secret.clone())
            .unwrap();

        assert_eq!(
            delegate.retrieve_secret(key.clone()).unwrap(),
            Some(secret)
        );

        delegate.delete_secret(key.clone()).unwrap();

        assert_eq!(delegate.retrieve_secret(key).unwrap(), None);
    }

    #[test]
    fn secrets_are_isolated_by_origin() {
        let delegate = DefaultCredentialManagementDelegate::default();

        let first = origin("https://example.com");
        let second = origin("https://example.org");

        delegate
            .store_secret(first.clone(), b"first".to_vec())
            .unwrap();

        delegate
            .store_secret(second.clone(), b"second".to_vec())
            .unwrap();

        assert_eq!(
            delegate.retrieve_secret(first).unwrap(),
            Some(b"first".to_vec())
        );

        assert_eq!(
            delegate.retrieve_secret(second).unwrap(),
            Some(b"second".to_vec())
        );
    }
}

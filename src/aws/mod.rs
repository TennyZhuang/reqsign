//! AWS service signer
//!
//! Only sigv4 has been supported.
mod config;
pub use config::Config as AwsConfig;

mod profile;
pub use profile::ConfigProfile as AwsConfigProfile;
pub use profile::ConfigProfiles as AwsConfigProfiles;
pub use profile::CredentialProfile as AwsCredentialProfile;
pub use profile::CredentialProfiles as AwsCredentialProfiles;

mod credential;
pub use credential::Credential as AwsCredential;
pub use credential::CredentialLoad as AwsCredentialLoad;
pub use credential::Loader as AwsLoader;

mod v4;
pub use v4::Signer as AwsV4Signer;

mod constants;

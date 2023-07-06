use std::collections::HashMap;
use std::env;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Write;
use std::sync::atomic::AtomicI64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::UNIX_EPOCH;

use anyhow::anyhow;
use anyhow::Result;
use async_trait::async_trait;
use http::header::CONTENT_LENGTH;
use log::debug;
use log::warn;
use quick_xml::de;
use reqwest::Client;
use serde::Deserialize;

use super::config::Config;
use super::profile::*;
use crate::aws::constants::*;
use crate::time::now;
use crate::time::parse_rfc3339;
use crate::time::DateTime;

/// Credential that holds the access_key and secret_key.
#[derive(Default, Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct Credential {
    /// Access key id for aws services.
    pub access_key_id: String,
    /// Secret access key for aws services.
    pub secret_access_key: String,
    /// Session token for aws services.
    pub session_token: Option<String>,
    /// Expiration time for this credential.
    pub expires_in: Option<DateTime>,
}

impl Credential {
    /// is current cred is valid?
    pub fn is_valid(&self) -> bool {
        if (self.access_key_id.is_empty() || self.secret_access_key.is_empty())
            && self.session_token.is_none()
        {
            return false;
        }
        // Take 120s as buffer to avoid edge cases.
        if let Some(valid) = self
            .expires_in
            .map(|v| v > now() + chrono::Duration::minutes(2))
        {
            return valid;
        }

        true
    }
}

/// Loader trait will try to load credential from different sources.
#[async_trait]
pub trait CredentialLoad: 'static + Send + Sync + Debug {
    /// Load credential from sources.
    ///
    /// - If succeed, return `Ok(Some(cred))`
    /// - If not found, return `Ok(None)`
    /// - If unexpected errors happened, return `Err(err)`
    async fn load_credential(&self, client: Client) -> Result<Option<Credential>>;
}

/// CredentialLoader will load credential from different methods.
#[cfg_attr(test, derive(Debug))]
pub struct Loader {
    client: Client,
    config: Config,

    disable_ec2_metadata: bool,
    customed_credential_loader: Option<Box<dyn CredentialLoad>>,

    credential: Arc<Mutex<Option<Credential>>>,
}

impl Loader {
    /// Create a new CredentialLoader
    pub fn new(client: Client, config: Config) -> Self {
        Self {
            client,
            config,

            disable_ec2_metadata: false,
            customed_credential_loader: None,

            credential: Arc::default(),
        }
    }

    /// Disable load from ec2 metadata.
    pub fn with_disable_ec2_metadata(mut self) -> Self {
        self.disable_ec2_metadata = true;
        self
    }

    /// Set customed credential loader.
    ///
    /// This loader will be used first.
    pub fn with_customed_credential_loader(mut self, f: Box<dyn CredentialLoad>) -> Self {
        self.customed_credential_loader = Some(f);
        self
    }

    /// Load credential.
    ///
    /// Resolution order:
    /// 1. Environment variables
    /// 2. Shared config (`~/.aws/config`, `~/.aws/credentials`)
    /// 3. Web Identity Tokens
    /// 4. ECS (IAM Roles for Tasks) & General HTTP credentials:
    /// 5. EC2 IMDSv2
    pub async fn load(&self) -> Result<Option<Credential>> {
        // Return cached credential if it has been loaded at least once.
        match self.credential.lock().expect("lock poisoned").clone() {
            Some(cred) if cred.is_valid() => return Ok(Some(cred)),
            _ => (),
        }

        let cred = self.load_inner().await?;

        let mut lock = self.credential.lock().expect("lock poisoned");
        *lock = cred.clone();

        Ok(cred)
    }

    async fn load_inner(&self) -> Result<Option<Credential>> {
        if let Ok(Some(cred)) = self
            .load_via_customed_credential_load()
            .await
            .map_err(|err| debug!("load credential via customed_credential_load failed: {err:?}"))
        {
            return Ok(Some(cred));
        }

        if let Ok(Some(cred)) = self
            .load_via_config()
            .map_err(|err| debug!("load credential via config failed: {err:?}"))
        {
            return Ok(Some(cred));
        }

        if let Ok(Some(cred)) = self
            .load_via_assume_role()
            .await
            .map_err(|err| debug!("load credential via assume_role failed: {err:?}"))
        {
            return Ok(Some(cred));
        }

        if let Ok(Some(cred)) = self
            .load_via_imds_v2()
            .await
            .map_err(|err| debug!("load credential via imds_v2 failed: {err:?}"))
        {
            return Ok(Some(cred));
        }

        Ok(None)
    }

    async fn load_via_customed_credential_load(&self) -> Result<Option<Credential>> {
        if let Some(loader) = &self.customed_credential_loader {
            loader.load_credential(self.client.clone()).await
        } else {
            Ok(None)
        }
    }

    fn load_via_config(&self) -> Result<Option<Credential>> {
        if let (Some(ak), Some(sk)) = (&self.config.access_key_id, &self.config.secret_access_key) {
            Ok(Some(Credential {
                access_key_id: ak.clone(),
                secret_access_key: sk.clone(),
                session_token: self.config.session_token.clone(),
                // Set expires_in to 10 minutes to enforce re-read
                // from file.
                expires_in: Some(now() + chrono::Duration::minutes(10)),
            }))
        } else {
            Ok(None)
        }
    }

    async fn load_via_imds_v2(&self) -> Result<Option<Credential>> {
        if self.disable_ec2_metadata {
            return Ok(None);
        }

        // Get ec2 metadata token
        let url = "http://169.254.169.254/latest/api/token";
        let req = self
            .client
            .put(url)
            .header(CONTENT_LENGTH, "0")
            .header("x-aws-ec2-metadata-token-ttl-seconds", "60");
        let resp = req.send().await?;
        if resp.status() != http::StatusCode::OK {
            let content = resp.text().await?;
            return Err(anyhow!(
                "request to AWS EC2 Metadata Services failed: {content}"
            ));
        }
        let ec2_token = resp.text().await?;

        // List all credentials that node has.
        let url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
        let req = self
            .client
            .get(url)
            .header("x-aws-ec2-metadata-token", &ec2_token);
        let resp = req.send().await?;
        if resp.status() != http::StatusCode::OK {
            let content = resp.text().await?;
            return Err(anyhow!(
                "request to AWS EC2 Metadata Services failed: {content}"
            ));
        }
        let content = resp.text().await?;
        let credential_list: Vec<_> = content.split('\n').collect();
        // credential list is empty, return None directly.
        if credential_list.is_empty() {
            return Ok(None);
        }
        let role_name = credential_list[0];

        // Get the credentials via role_name.
        let url =
            format!("http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}");
        let req = self
            .client
            .get(&url)
            .header("x-aws-ec2-metadata-token", &ec2_token);
        let resp = req.send().await?;
        if resp.status() != http::StatusCode::OK {
            let content = resp.text().await?;
            return Err(anyhow!(
                "request to AWS EC2 Metadata Services failed: {content}"
            ));
        }

        let content = resp.text().await?;
        let resp: Ec2MetadataIamSecurityCredentials = serde_json::from_str(&content)?;
        if resp.code != "Success" {
            return Err(anyhow!(
                "request to AWS EC2 Metadata Services failed: {content}"
            ));
        }

        let cred = Credential {
            access_key_id: resp.access_key_id,
            secret_access_key: resp.secret_access_key,
            session_token: Some(resp.token),
            expires_in: Some(parse_rfc3339(&resp.expiration)?),
        };

        Ok(Some(cred))
    }

    async fn load_via_assume_role(&self) -> Result<Option<Credential>> {
        let role_arn = match &self.config.role_arn {
            Some(role_arn) => role_arn,
            None => return Ok(None),
        };
        let role_session_name = &self.config.role_session_name;

        let endpoint = self.sts_endpoint()?;

        // Construct request to AWS STS Service.
        let mut url = format!("https://{endpoint}/?Action=AssumeRole&RoleArn={role_arn}&Version=2011-06-15&RoleSessionName={role_session_name}");
        if let Some(external_id) = &self.config.external_id {
            write!(url, "&ExternalId={external_id}")?;
        }
        let req = self.client.get(&url).header(
            http::header::CONTENT_TYPE.as_str(),
            "application/x-www-form-urlencoded",
        );

        let resp = req.send().await?;
        if resp.status() != http::StatusCode::OK {
            let content = resp.text().await?;
            return Err(anyhow!("request to AWS STS Services failed: {content}"));
        }

        let resp: AssumeRoleResponse = de::from_str(&resp.text().await?)?;
        let resp_cred = resp.result.credentials;

        let cred = Credential {
            access_key_id: resp_cred.access_key_id,
            secret_access_key: resp_cred.secret_access_key,
            session_token: Some(resp_cred.session_token),
            expires_in: Some(parse_rfc3339(&resp_cred.expiration)?),
        };

        Ok(Some(cred))
    }

    /// Get the sts endpoint.
    ///
    /// The returning format may look like `sts.{region}.amazonaws.com`
    ///
    /// # Notes
    ///
    /// AWS could have different sts endpoint based on it's region.
    /// We can check them by region name.
    ///
    /// ref: https://github.com/awslabs/aws-sdk-rust/blob/31cfae2cf23be0c68a47357070dea1aee9227e3a/sdk/sts/src/aws_endpoint.rs
    fn sts_endpoint(&self) -> Result<String> {
        // use regional sts if sts_regional_endpoints has been set.
        if self.config.sts_regional_endpoints == "regional" {
            let region = self.config.region.clone().ok_or_else(|| {
                anyhow!("sts_regional_endpoints set to reginal, but region is not set")
            })?;
            if region.starts_with("cn-") {
                Ok(format!("sts.{region}.amazonaws.com.cn"))
            } else {
                Ok(format!("sts.{region}.amazonaws.com"))
            }
        } else {
            let region = self.config.region.clone().unwrap_or_default();
            if region.starts_with("cn") {
                // TODO: seems aws china doesn't support global sts?
                Ok("sts.amazonaws.com.cn".to_string())
            } else {
                Ok("sts.amazonaws.com".to_string())
            }
        }
    }
}

/// Load credential from environment variables.
#[derive(Default)]
struct EnvLoader {}

impl Debug for EnvLoader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvLoader").finish_non_exhaustive()
    }
}

#[async_trait]
impl CredentialLoad for EnvLoader {
    async fn load_credential(&self, _: Client) -> Result<Option<Credential>> {
        let envs = env::vars().collect::<HashMap<_, _>>();

        let access_key_id = match envs.get(AWS_ACCESS_KEY_ID) {
            Some(v) => v.to_string(),
            None => return Ok(None),
        };
        let secret_access_key = match envs.get(AWS_SECRET_ACCESS_KEY) {
            Some(v) => v.to_string(),
            None => return Ok(None),
        };

        // Allow both AWS_SESSION_TOKEN and AWS_SECURITY_TOKEN.
        let token = envs
            .get(AWS_SESSION_TOKEN)
            .or(envs.get(AWS_SECURITY_TOKEN))
            .cloned();

        // Set expires_in to 1 hour to enforce re-read from env.
        let expires_in = match envs.get(AWS_CREDENTIAL_EXPIRATION) {
            Some(v) => Some(parse_rfc3339(v)?),
            None => Some(now() + chrono::Duration::hours(1)),
        };

        let cred = Credential {
            access_key_id,
            secret_access_key,
            session_token: token,
            expires_in,
        };

        Ok(Some(cred))
    }
}

/// Load credential from environment variables.
struct CredentialProfileLoader {
    path: String,
    profile_name: String,

    /// The timestampe for last updated time of profiles.
    last_updated: AtomicI64,
    profiles: Arc<Mutex<CredentialProfiles>>,
}

impl Debug for CredentialProfileLoader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialProfileLoader")
            .field("path", &self.path)
            .field("profile_name", &self.profile_name)
            .finish_non_exhaustive()
    }
}

impl Default for CredentialProfileLoader {
    fn default() -> Self {
        Self {
            path: "~/.aws/credentials".to_string(),
            profile_name: "default".to_string(),
            last_updated: AtomicI64::default(),
            profiles: Arc::default(),
        }
    }
}

impl CredentialProfileLoader {
    /// Get credential profile via this loader.
    pub async fn get_profile(&self, name: &str) -> Result<Arc<CredentialProfile>> {
        let meta = tokio::fs::metadata(&self.path)
            .await
            .map_err(|err| anyhow!("get metadata of credential file failed: {err}"))?;
        let last_modified = meta.modified()?.duration_since(UNIX_EPOCH)?.as_secs();

        let profile = if self.last_updated.load(Ordering::Relaxed) >= last_modified as i64 {
            self.profiles.lock().unwrap().get(name)
        } else {
            let content = tokio::fs::read_to_string(&self.path).await?;
            let profiles = CredentialProfiles::new(&content)?;

            // Update last_updated so that we don't need to read again.
            self.last_updated
                .store(now().timestamp(), Ordering::Relaxed);
            let profile = profiles.get(name);

            *self.profiles.lock().unwrap() = profiles;
            profile
        };

        Ok(profile)
    }
}

#[async_trait]
impl CredentialLoad for CredentialProfileLoader {
    async fn load_credential(&self, _: Client) -> Result<Option<Credential>> {
        let profile = self.get_profile(&self.profile_name).await?;

        if let (Some(access_key_id), Some(secret_access_key)) =
            (&profile.aws_access_key_id, &profile.aws_secret_access_key)
        {
            let cred = Credential {
                access_key_id: access_key_id.clone(),
                secret_access_key: secret_access_key.clone(),
                session_token: profile.aws_session_token.clone(),
                // Enforce re-read from file after 1 hour.
                expires_in: Some(now() + chrono::Duration::hours(1)),
            };

            Ok(Some(cred))
        } else {
            Ok(None)
        }
    }
}

/// Load credential from config variables.
struct ConfigProfileLoader {
    path: String,
    profile_name: String,

    /// The timestampe for last updated time of profiles.
    last_updated: AtomicI64,
    profiles: Arc<Mutex<ConfigProfiles>>,
}

impl Debug for ConfigProfileLoader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigProfileLoader")
            .field("path", &self.path)
            .field("profile_name", &self.profile_name)
            .finish_non_exhaustive()
    }
}

impl Default for ConfigProfileLoader {
    fn default() -> Self {
        Self {
            path: "~/.aws/config".to_string(),
            profile_name: "default".to_string(),
            last_updated: AtomicI64::default(),
            profiles: Arc::default(),
        }
    }
}

impl ConfigProfileLoader {
    /// Get credential profile via this loader.
    pub async fn get_profile(&self, name: &str) -> Result<Arc<ConfigProfile>> {
        let meta = tokio::fs::metadata(&self.path)
            .await
            .map_err(|err| anyhow!("get metadata of config file failed: {err}"))?;
        let last_modified = meta.modified()?.duration_since(UNIX_EPOCH)?.as_secs();

        let profile = if self.last_updated.load(Ordering::Relaxed) >= last_modified as i64 {
            self.profiles.lock().unwrap().get(name)
        } else {
            let content = tokio::fs::read_to_string(&self.path).await?;
            let profiles = ConfigProfiles::new(&content)?;

            // Update last_updated so that we don't need to read again.
            self.last_updated
                .store(now().timestamp(), Ordering::Relaxed);
            let profile = profiles.get(name);

            *self.profiles.lock().unwrap() = profiles;
            profile
        };

        Ok(profile)
    }
}

#[async_trait]
impl CredentialLoad for ConfigProfileLoader {
    async fn load_credential(&self, _: Client) -> Result<Option<Credential>> {
        let profile = self.get_profile(&self.profile_name).await?;

        if let (Some(access_key_id), Some(secret_access_key)) =
            (&profile.aws_access_key_id, &profile.aws_secret_access_key)
        {
            let cred = Credential {
                access_key_id: access_key_id.clone(),
                secret_access_key: secret_access_key.clone(),
                session_token: profile.aws_session_token.clone(),
                // Enforce re-read from file after 1 hour.
                expires_in: Some(now() + chrono::Duration::hours(1)),
            };

            Ok(Some(cred))
        } else {
            Ok(None)
        }
    }
}

/// Load credential via EC2 instance metadata.
struct Ec2InstanceMetadataLoader {
    /// Token and it's expire time.
    token: Arc<Mutex<(String, DateTime)>>,
}

impl Debug for Ec2InstanceMetadataLoader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ec2InstanceMetadataLoader")
            .finish_non_exhaustive()
    }
}

impl Default for Ec2InstanceMetadataLoader {
    fn default() -> Self {
        Self {
            token: Arc::new(Mutex::new((String::default(), DateTime::MIN_UTC))),
        }
    }
}

impl Ec2InstanceMetadataLoader {
    /// TODO: we should support customed metadata endpoint.
    async fn get_ec2_metadata_token(&self, client: Client) -> Result<String> {
        {
            let (token, expires_in) = self.token.lock().unwrap().clone();
            if !token.is_empty() && expires_in > now() {
                return Ok(token);
            }
        }

        // Get ec2 metadata token
        let url = "http://169.254.169.254/latest/api/token";
        let req = client
            .put(url)
            .timeout(Duration::from_secs(1))
            .header(CONTENT_LENGTH, "0")
            .header("x-aws-ec2-metadata-token-ttl-seconds", "21600");
        let resp = req.send().await?;
        if resp.status() != http::StatusCode::OK {
            let content = resp.text().await?;
            return Err(anyhow!(
                "request to AWS EC2 Metadata Services failed: {content}"
            ));
        }
        let token = resp.text().await?;

        // 21600s is the default value from AWS CLI.
        // We will minus 120s to avoid time skew.
        //
        // We will allow user to configure it in the future.
        let expires_in = now() + chrono::Duration::seconds(21600 - 120);

        *self.token.lock().unwrap() = (token.clone(), expires_in);
        Ok(token)
    }
}

#[async_trait]
impl CredentialLoad for Ec2InstanceMetadataLoader {
    async fn load_credential(&self, client: Client) -> Result<Option<Credential>> {
        // If AWS_EC2_METADATA_DISABLED has been set to true, we should
        // ignore this loader directly.
        if let Ok(v) = env::var(AWS_EC2_METADATA_DISABLED) {
            if v == "true" {
                return Ok(None);
            }
        }

        let token = self.get_ec2_metadata_token(client.clone()).await?;

        // List all credentials that node has.
        let url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
        let req = client
            .get(url)
            .timeout(Duration::from_secs(1))
            .header("x-aws-ec2-metadata-token", &token);
        let resp = req.send().await?;
        if resp.status() != http::StatusCode::OK {
            let content = resp.text().await?;
            return Err(anyhow!(
                "request to AWS EC2 Metadata Services failed: {content}"
            ));
        }
        let role_name = resp.text().await?;

        // Get the credentials via role_name.
        let url =
            format!("http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}");
        let req = client
            .get(&url)
            .timeout(Duration::from_secs(1))
            .header("x-aws-ec2-metadata-token", &token);
        let resp = req.send().await?;
        if resp.status() != http::StatusCode::OK {
            let content = resp.text().await?;
            return Err(anyhow!(
                "request to AWS EC2 Metadata Services failed: {content}"
            ));
        }

        let content = resp.text().await?;
        let resp: Ec2MetadataIamSecurityCredentials = serde_json::from_str(&content)?;
        if resp.code != "Success" {
            return Err(anyhow!(
                "request to AWS EC2 Metadata Services failed: {content}"
            ));
        }

        let cred = Credential {
            access_key_id: resp.access_key_id,
            secret_access_key: resp.secret_access_key,
            session_token: Some(resp.token),
            expires_in: Some(parse_rfc3339(&resp.expiration)?),
        };

        Ok(Some(cred))
    }
}

/// Load credential via assume role with web identity.
struct AssumeRoleWithWebIdentityLoader {
    profile_name: String,
    profile_loader: ConfigProfileLoader,
}

impl Debug for AssumeRoleWithWebIdentityLoader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AssumeRoleWithWebIdentityLoader")
            .finish_non_exhaustive()
    }
}

impl Default for AssumeRoleWithWebIdentityLoader {
    fn default() -> Self {
        Self {
            profile_name: "default".to_string(),
            profile_loader: ConfigProfileLoader::default(),
        }
    }
}

impl AssumeRoleWithWebIdentityLoader {
    async fn get_web_identity_token_file(&self) -> Option<String> {
        if let Ok(v) = env::var(AWS_WEB_IDENTITY_TOKEN_FILE) {
            return Some(v);
        }

        let profile = self
            .profile_loader
            .get_profile(&self.profile_name)
            .await
            .ok()?;

        profile.web_identity_token_file.clone()
    }

    async fn get_role_arn(&self) -> Option<String> {
        if let Ok(v) = env::var(AWS_ROLE_ARN) {
            return Some(v);
        }

        let profile = self
            .profile_loader
            .get_profile(&self.profile_name)
            .await
            .ok()?;

        profile.role_arn.clone()
    }

    async fn get_role_session_name(&self) -> Option<String> {
        if let Ok(v) = env::var(AWS_ROLE_SESSION_NAME) {
            return Some(v);
        }

        let profile = self
            .profile_loader
            .get_profile(&self.profile_name)
            .await
            .ok()?;

        profile.role_session_name.clone()
    }

    async fn get_sts_regional_endpoints(&self) -> Option<String> {
        if let Ok(v) = env::var(AWS_STS_REGIONAL_ENDPOINTS) {
            return Some(v);
        }

        let profile = self
            .profile_loader
            .get_profile(&self.profile_name)
            .await
            .ok()?;

        profile.sts_regional_endpoints.clone()
    }

    async fn get_region(&self) -> Option<String> {
        if let Ok(v) = env::var(AWS_REGION) {
            return Some(v);
        }

        let profile = self
            .profile_loader
            .get_profile(&self.profile_name)
            .await
            .ok()?;

        profile.region.clone()
    }

    /// Get the sts endpoint.
    ///
    /// The returning format may look like `sts.{region}.amazonaws.com`
    ///
    /// # Notes
    ///
    /// AWS could have different sts endpoint based on it's region.
    /// We can check them by region name.
    ///
    /// ref: https://github.com/awslabs/aws-sdk-rust/blob/31cfae2cf23be0c68a47357070dea1aee9227e3a/sdk/sts/src/aws_endpoint.rs
    async fn get_sts_endpoint(&self) -> Result<String> {
        let sts_regional_endpoints = self
            .get_sts_regional_endpoints()
            .await
            .unwrap_or_else(|| "legacy".to_string());

        // use regional sts if sts_regional_endpoints has been set.
        if sts_regional_endpoints == "regional" {
            let region = self.get_region().await.ok_or_else(|| {
                anyhow!("sts_regional_endpoints set to reginal, but region is not set")
            })?;
            if region.starts_with("cn-") {
                Ok(format!("sts.{region}.amazonaws.com.cn"))
            } else {
                Ok(format!("sts.{region}.amazonaws.com"))
            }
        } else {
            let region = self.get_region().await.unwrap_or_default();
            if region.starts_with("cn") {
                // TODO: seems aws china doesn't support global sts?
                Ok("sts.amazonaws.com.cn".to_string())
            } else {
                Ok("sts.amazonaws.com".to_string())
            }
        }
    }
}

#[async_trait]
impl CredentialLoad for AssumeRoleWithWebIdentityLoader {
    async fn load_credential(&self, client: Client) -> Result<Option<Credential>> {
        let token_file = match self.get_web_identity_token_file().await {
            Some(v) => v,
            None => return Ok(None),
        };

        let role_arn = match self.get_role_arn().await {
            Some(v) => v,
            None => {
                warn!("Current environment is configured to assume role with web identity but has no role ARN configured");
                return Ok(None);
            }
        };

        let role_session_name = self
            .get_role_session_name()
            .await
            .unwrap_or_else(|| "reqsign".to_string());

        let token = tokio::fs::read_to_string(token_file).await?;
        let endpoint = self.get_sts_endpoint().await?;

        // Construct request to AWS STS Service.
        let url = format!("https://{endpoint}/?Action=AssumeRoleWithWebIdentity&RoleArn={role_arn}&WebIdentityToken={token}&Version=2011-06-15&RoleSessionName={role_session_name}");
        let req = client.get(&url).header(
            http::header::CONTENT_TYPE.as_str(),
            "application/x-www-form-urlencoded",
        );

        let resp = req.send().await?;
        if resp.status() != http::StatusCode::OK {
            let content = resp.text().await?;
            return Err(anyhow!("request to AWS STS Services failed: {content}"));
        }

        let resp: AssumeRoleWithWebIdentityResponse = de::from_str(&resp.text().await?)?;
        let resp_cred = resp.result.credentials;

        let cred = Credential {
            access_key_id: resp_cred.access_key_id,
            secret_access_key: resp_cred.secret_access_key,
            session_token: Some(resp_cred.session_token),
            expires_in: Some(parse_rfc3339(&resp_cred.expiration)?),
        };

        Ok(Some(cred))
    }
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityResponse {
    #[serde(rename = "AssumeRoleWithWebIdentityResult")]
    result: AssumeRoleWithWebIdentityResult,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityResult {
    credentials: AssumeRoleWithWebIdentityCredentials,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: String,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleResponse {
    #[serde(rename = "AssumeRoleResult")]
    result: AssumeRoleResult,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleResult {
    credentials: AssumeRoleCredentials,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: String,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct Ec2MetadataIamSecurityCredentials {
    access_key_id: String,
    secret_access_key: String,
    token: String,
    expiration: String,

    code: String,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::{env, vec};

    use anyhow::Result;
    use http::{Request, StatusCode};
    use once_cell::sync::Lazy;
    use quick_xml::de;
    use reqwest::Client;
    use tokio::runtime::Runtime;

    use super::*;
    use crate::aws::v4::Signer;
    use std::fs;

    static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Should create a tokio runtime")
    });

    #[test]
    fn test_credential_env_loader_without_env() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars_unset(vec![AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY], || {
            RUNTIME.block_on(async {
                let l = Loader::new(reqwest::Client::new(), Config::default())
                    .with_disable_ec2_metadata();
                let x = l.load().await.expect("load must succeed");
                assert!(x.is_none());
            })
        });
    }

    #[test]
    fn test_credential_env_loader_with_env() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars(
            vec![
                (AWS_ACCESS_KEY_ID, Some("access_key_id")),
                (AWS_SECRET_ACCESS_KEY, Some("secret_access_key")),
            ],
            || {
                RUNTIME.block_on(async {
                    let l = Loader::new(Client::new(), Config::default().from_env());
                    let x = l.load().await.expect("load must succeed");

                    let x = x.expect("must load succeed");
                    assert_eq!("access_key_id", x.access_key_id);
                    assert_eq!("secret_access_key", x.secret_access_key);
                })
            },
        );
    }

    #[test]
    fn test_credential_profile_loader_from_config() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars(
            vec![
                (AWS_ACCESS_KEY_ID, None),
                (AWS_SECRET_ACCESS_KEY, None),
                (
                    AWS_CONFIG_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/default_config",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    )),
                ),
                (
                    AWS_SHARED_CREDENTIALS_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/not_exist",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    )),
                ),
            ],
            || {
                RUNTIME.block_on(async {
                    let l = Loader::new(Client::new(), Config::default().from_env().from_profile());
                    let x = l.load().await.unwrap().unwrap();
                    assert_eq!("config_access_key_id", x.access_key_id);
                    assert_eq!("config_secret_access_key", x.secret_access_key);
                })
            },
        );
    }

    #[test]
    fn test_credential_profile_loader_from_shared() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars(
            vec![
                (AWS_ACCESS_KEY_ID, None),
                (AWS_SECRET_ACCESS_KEY, None),
                (
                    AWS_CONFIG_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/not_exist",
                        env::current_dir()
                            .expect("load must exist")
                            .to_string_lossy()
                    )),
                ),
                (
                    AWS_SHARED_CREDENTIALS_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/default_credential",
                        env::current_dir()
                            .expect("load must exist")
                            .to_string_lossy()
                    )),
                ),
            ],
            || {
                RUNTIME.block_on(async {
                    let l = Loader::new(Client::new(), Config::default().from_env().from_profile());
                    let x = l.load().await.unwrap().unwrap();
                    assert_eq!("shared_access_key_id", x.access_key_id);
                    assert_eq!("shared_secret_access_key", x.secret_access_key);
                })
            },
        );
    }

    /// AWS_SHARED_CREDENTIALS_FILE should be taken first.
    #[test]
    fn test_credential_profile_loader_from_both() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars(
            vec![
                (AWS_ACCESS_KEY_ID, None),
                (AWS_SECRET_ACCESS_KEY, None),
                (
                    AWS_CONFIG_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/default_config",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    )),
                ),
                (
                    AWS_SHARED_CREDENTIALS_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/default_credential",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    )),
                ),
            ],
            || {
                RUNTIME.block_on(async {
                    let l = Loader::new(Client::new(), Config::default().from_env().from_profile());
                    let x = l.load().await.expect("load must success").unwrap();
                    assert_eq!("shared_access_key_id", x.access_key_id);
                    assert_eq!("shared_secret_access_key", x.secret_access_key);
                })
            },
        );
    }

    #[test]
    fn test_signer_with_web_loader() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        dotenv::from_filename(".env").ok();

        if env::var("REQSIGN_AWS_S3_TEST").is_err()
            || env::var("REQSIGN_AWS_S3_TEST").unwrap() != "on"
        {
            return Ok(());
        }

        // Ignore test if role_arn not set
        let role_arn = if let Ok(v) = env::var("REQSIGN_AWS_ROLE_ARN") {
            v
        } else {
            return Ok(());
        };

        // let provider_arn = env::var("REQSIGN_AWS_PROVIDER_ARN").expect("REQSIGN_AWS_PROVIDER_ARN not exist");
        let region = env::var("REQSIGN_AWS_S3_REGION").expect("REQSIGN_AWS_S3_REGION not exist");

        let github_token = env::var("GITHUB_ID_TOKEN").expect("GITHUB_ID_TOKEN not exist");
        let file_path = format!(
            "{}/testdata/services/aws/web_identity_token_file",
            env::current_dir()
                .expect("current_dir must exist")
                .to_string_lossy()
        );
        fs::write(&file_path, github_token)?;

        temp_env::with_vars(
            vec![
                (AWS_REGION, Some(&region)),
                (AWS_ROLE_ARN, Some(&role_arn)),
                (AWS_WEB_IDENTITY_TOKEN_FILE, Some(&file_path)),
            ],
            || {
                RUNTIME.block_on(async {
                    let config = Config::default().from_env();
                    let loader = Loader::new(reqwest::Client::new(), config);

                    let signer = Signer::new("s3", &region);

                    let endpoint = format!("https://s3.{}.amazonaws.com/opendal-testing", region);
                    let mut req = Request::new("");
                    *req.method_mut() = http::Method::GET;
                    *req.uri_mut() =
                        http::Uri::from_str(&format!("{}/{}", endpoint, "not_exist_file")).unwrap();

                    let cred = loader
                        .load()
                        .await
                        .expect("credential must be valid")
                        .unwrap();

                    signer.sign(&mut req, &cred).expect("sign must success");

                    debug!("signed request url: {:?}", req.uri().to_string());
                    debug!("signed request: {:?}", req);

                    let client = Client::new();
                    let resp = client.execute(req.try_into().unwrap()).await.unwrap();

                    let status = resp.status();
                    debug!("got response: {:?}", resp);
                    debug!("got response content: {:?}", resp.text().await.unwrap());
                    assert_eq!(status, StatusCode::NOT_FOUND);
                })
            },
        );

        Ok(())
    }

    #[test]
    fn test_parse_assume_role_with_web_identity_response() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let content = r#"<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Audience>test_audience</Audience>
    <AssumedRoleUser>
      <AssumedRoleId>role_id:reqsign</AssumedRoleId>
      <Arn>arn:aws:sts::123:assumed-role/reqsign/reqsign</Arn>
    </AssumedRoleUser>
    <Provider>arn:aws:iam::123:oidc-provider/example.com/</Provider>
    <Credentials>
      <AccessKeyId>access_key_id</AccessKeyId>
      <SecretAccessKey>secret_access_key</SecretAccessKey>
      <SessionToken>session_token</SessionToken>
      <Expiration>2022-05-25T11:45:17Z</Expiration>
    </Credentials>
    <SubjectFromWebIdentityToken>subject</SubjectFromWebIdentityToken>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata>
    <RequestId>b1663ad1-23ab-45e9-b465-9af30b202eba</RequestId>
  </ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>"#;

        let resp: AssumeRoleWithWebIdentityResponse =
            de::from_str(content).expect("xml deserialize must success");

        assert_eq!(&resp.result.credentials.access_key_id, "access_key_id");
        assert_eq!(
            &resp.result.credentials.secret_access_key,
            "secret_access_key"
        );
        assert_eq!(&resp.result.credentials.session_token, "session_token");
        assert_eq!(&resp.result.credentials.expiration, "2022-05-25T11:45:17Z");

        Ok(())
    }

    #[test]
    fn test_parse_assume_role_response() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let content = r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
  <SourceIdentity>Alice</SourceIdentity>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/demo/TestAR</Arn>
      <AssumedRoleId>ARO123EXAMPLE123:TestAR</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>ASIAIOSFODNN7EXAMPLE</AccessKeyId>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY</SecretAccessKey>
      <SessionToken>
       AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQW
       LWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGd
       QrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU
       9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz
       +scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==
      </SessionToken>
      <Expiration>2019-11-09T13:34:41Z</Expiration>
    </Credentials>
    <PackedPolicySize>6</PackedPolicySize>
  </AssumeRoleResult>
  <ResponseMetadata>
    <RequestId>c6104cbe-af31-11e0-8154-cbc7ccf896c7</RequestId>
  </ResponseMetadata>
</AssumeRoleResponse>"#;

        let resp: AssumeRoleResponse = de::from_str(content).expect("xml deserialize must success");

        assert_eq!(
            &resp.result.credentials.access_key_id,
            "ASIAIOSFODNN7EXAMPLE"
        );
        assert_eq!(
            &resp.result.credentials.secret_access_key,
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY"
        );
        assert_eq!(
            &resp.result.credentials.session_token,
            "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQW
       LWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGd
       QrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU
       9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz
       +scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA=="
        );
        assert_eq!(&resp.result.credentials.expiration, "2019-11-09T13:34:41Z");

        Ok(())
    }
}

use anyhow::Result;
use ini::Ini;
use std::{collections::HashMap, sync::Arc};

/// ConfigProfiles carries all content from `~/.aws/config`.
#[derive(Default, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct ConfigProfiles {
    map: HashMap<String, Arc<ConfigProfile>>,
}

/// ConfigProfile carries all content from a profile in `~/.aws/config`.
///
/// Please note that not all fields are stored yet. We removed all awscli
/// related fields and s3 related fields.
///
/// All fields are listed in: <https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html>
#[derive(Default, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct ConfigProfile {
    /// AWS Access Key ID
    pub aws_access_key_id: Option<String>,
    /// AWS Secret Access Key
    pub aws_secret_access_key: Option<String>,
    /// AWS Session Token
    pub aws_session_token: Option<String>,

    /// TODO: we don't support `credential_process` yet.
    ///
    /// Specifies an external command that the AWS CLI runs to generate or
    /// retrieve authentication credentials to use for this command.
    pub credential_process: Option<String>,
    /// Used within Amazon EC2 instances or containers to specify where the
    /// AWS CLI can find credentials to use to assume the role you specified
    /// with the `role_arn` parameter.
    ///
    /// You cannot specify both `source_profile` and `credential_source` in the
    /// same profile.
    ///
    /// This parameter can have one of three values:
    ///
    /// - `Environment` – Specifies that the AWS CLI is to retrieve source
    ///   credentials from environment variables.
    /// - `Ec2InstanceMetadata` – Specifies that the AWS CLI is to use the IAM
    ///   role attached to the EC2 instance profile to get source credentials.
    /// - `EcsContainer` – Specifies that the AWS CLI is to use the IAM role
    ///   attached to the ECS container as source credentials.
    ///
    /// # TODO
    ///
    /// EcsContainer is not supported yet.
    ///
    /// Reference: <https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html>
    pub credential_source: Option<String>,
    /// Specifies the maximum duration of the role session, in seconds.
    ///
    /// The value can range from 900 seconds (15 minutes) up to the maximum
    /// session duration setting for the role (which can be a maximum of
    /// 43200). This is an optional parameter and by default, the value is set
    /// to 3600 seconds.
    pub duration_seconds: Option<usize>,
    /// Specifies a unique identifier that is used by third parties to assume
    /// a role in their customers' accounts.
    ///
    /// This maps to the `ExternalId` parameter in the `AssumeRole` operation.
    /// This parameter is needed only if the trust policy for the role
    /// specifies a value for `ExternalId`.
    ///
    /// For more information, see [How to use an external ID when granting access to your AWS resources to a third party](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html) in the IAM User Guide.
    pub external_id: Option<String>,
    /// The identification number of an MFA device to use when assuming a
    /// role. This is mandatory only if the trust policy of the role being
    /// assumed includes a condition that requires MFA authentication. The
    /// value can be either a serial number for a hardware device (such as
    /// `GAHT12345678`) or an Amazon Resource Name (ARN) for a virtual MFA
    /// device (such as `arn:aws:iam::123456789012:mfa/user`).
    pub mfa_serial: Option<String>,
    /// Specifies the AWS Region to send requests to for commands requested
    /// using this profile.
    pub region: Option<String>,
    /// Specifies the Amazon Resource Name (ARN) of an IAM role that you want
    /// to use to run the AWS CLI commands. You must also specify one of the
    /// following parameters to identify the credentials that have permission
    /// to assume this role:
    ///
    /// - `source_profile`
    /// - `credential_source`
    pub role_arn: Option<String>,
    /// Specifies the name to attach to the role session.
    ///
    /// This value is provided to the `RoleSessionName` parameter when the AWS
    /// CLI calls the `AssumeRole` operation, and becomes part of the assumed
    /// role user ARN: `arn:aws:sts::123456789012:assumed-role/role_name/role_session_name`.
    ///
    /// This is an optional parameter. If you do not provide this value, a
    /// session name is generated automatically.
    pub role_session_name: Option<String>,
    /// Specifies a named profile with long-term credentials that the AWS CLI
    /// can use to assume a role that you specified with the `role_arn`
    /// parameter.
    pub source_profile: Option<String>,
    /// TODO: we don't support `sso_account_id` yet.
    ///
    /// Specifies the AWS account ID that contains the IAM role with the
    /// permission that you want to grant to the associated IAM Identity
    /// Center user.
    pub sso_account_id: Option<String>,
    /// TODO: we don't support `sso_region` yet.
    ///
    /// Specifies the AWS Region that contains the AWS access portal host.
    /// This is separate from, and can be a different Region than the default
    /// CLI region parameter.
    pub sso_region: Option<String>,
    /// TODO: we don't support `sso_registration_scopes` yet.
    ///
    /// A comma-delimited list of scopes to be authorized for the `sso-session`.
    /// Scopes authorize access to IAM Identity Center bearer token authorized
    /// endpoints. A valid scope is a string, such as sso:account:access. This
    /// setting isn't applicable to the legacy non-refreshable configuration.
    pub sso_registration_scopes: Option<String>,
    /// TODO: we don't support `sso_role_name` yet.
    ///
    /// Specifies the friendly name of the IAM role that defines the user's permissions when using this profile.
    pub sso_role_name: Option<String>,
    /// TODO: we don't support `sso_start_url` yet.
    ///
    /// Specifies the URL that points to the organization's AWS access portal.
    /// The AWS CLI uses this URL to establish a session with the IAM Identity
    /// Center service to authenticate its users.
    pub sso_start_url: Option<String>,
    /// Specifies the path to a file that contains an OAuth 2.0 access token
    /// or OpenID Connect ID token that is provided by an identity provider.
    ///
    /// The AWS CLI loads the contents of this file and passes it as the WebIdentityToken argument to the AssumeRoleWithWebIdentity operation.
    pub web_identity_token_file: Option<String>,
    /// By default, AWS Security Token Service (AWS STS) is available as a
    /// global service, and all AWS STS requests go to a single endpoint at
    /// <https://sts.amazonaws.com>.
    ///
    /// This setting specifies how the SDK or tool determines the AWS service endpoint that it uses to talk to the AWS Security Token Service (AWS STS).
    ///
    /// Default value: `legacy`
    /// Valid values:
    ///   - `legacy`
    ///   - `regional`
    pub sts_regional_endpoints: Option<String>,
}

impl ConfigProfiles {
    /// Create a new credential profile from given path.
    pub fn new(content: &str) -> Result<Self> {
        let conf = Ini::load_from_str(content)?;

        let mut map: HashMap<_, _, _> = HashMap::default();

        for section in conf.sections() {
            // All profiles are stored in named section, we can ignore the
            // top level section.
            let section = if let Some(v) = section {
                v
            } else {
                continue;
            };

            let props = conf
                .section(Some(section))
                .expect("section is listed but not found, must be a bug of rust-init");

            let mut profile = ConfigProfile::default();
            if let Some(v) = props.get("aws_access_key_id") {
                profile.aws_access_key_id = Some(v.to_string())
            }
            if let Some(v) = props.get("aws_secret_access_key") {
                profile.aws_secret_access_key = Some(v.to_string())
            }
            if let Some(v) = props.get("aws_session_token") {
                profile.aws_session_token = Some(v.to_string())
            }
            if let Some(v) = props.get("aws_session_token") {
                profile.aws_session_token = Some(v.to_string())
            }
            if let Some(v) = props.get("credential_process") {
                profile.credential_process = Some(v.to_string())
            }
            if let Some(v) = props.get("credential_source") {
                profile.credential_source = Some(v.to_string())
            }
            if let Some(v) = props.get("duration_seconds") {
                profile.duration_seconds = Some(v.parse()?);
            }
            if let Some(v) = props.get("external_id") {
                profile.external_id = Some(v.to_string())
            }
            if let Some(v) = props.get("mfa_serial") {
                profile.mfa_serial = Some(v.to_string())
            }
            if let Some(v) = props.get("region") {
                profile.region = Some(v.to_string())
            }
            if let Some(v) = props.get("role_arn") {
                profile.role_arn = Some(v.to_string())
            }
            if let Some(v) = props.get("role_session_name") {
                profile.role_session_name = Some(v.to_string())
            }
            if let Some(v) = props.get("source_profile") {
                profile.source_profile = Some(v.to_string())
            }
            if let Some(v) = props.get("sso_account_id") {
                profile.sso_account_id = Some(v.to_string())
            }
            if let Some(v) = props.get("sso_region") {
                profile.sso_region = Some(v.to_string())
            }
            if let Some(v) = props.get("sso_registration_scopes") {
                profile.sso_registration_scopes = Some(v.to_string())
            }
            if let Some(v) = props.get("sso_role_name") {
                profile.sso_role_name = Some(v.to_string())
            }
            if let Some(v) = props.get("sso_start_url") {
                profile.sso_start_url = Some(v.to_string())
            }
            if let Some(v) = props.get("web_identity_token_file") {
                profile.web_identity_token_file = Some(v.to_string())
            }
            if let Some(v) = props.get("sts_regional_endpoints") {
                profile.sts_regional_endpoints = Some(v.to_string())
            }

            // Config file's section has `profile` prefix.
            let section = section
                // Strip `profile` prefix
                .strip_prefix("profile")
                .unwrap_or(section)
                .trim()
                .to_string();
            map.insert(section, Arc::new(profile));
        }

        Ok(ConfigProfiles { map })
    }

    /// Get profile with given profile name.
    ///
    /// Return default value if not exist.
    pub fn get(&self, profile: &str) -> Arc<ConfigProfile> {
        self.map.get(profile).cloned().unwrap_or_default()
    }
}

/// CredentialProfiles carries all content from `~/.aws/credentials`.
#[derive(Default, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct CredentialProfiles {
    map: HashMap<String, Arc<CredentialProfile>>,
}

/// CredentialProfile carries all content from a profile in `~/.aws/credentials`.
#[derive(Default, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct CredentialProfile {
    /// AWS Access Key ID
    pub aws_access_key_id: Option<String>,
    /// AWS Secret Access Key
    pub aws_secret_access_key: Option<String>,
    /// AWS Session Token
    pub aws_session_token: Option<String>,
}

impl CredentialProfiles {
    /// Create a new credential profile from given path.
    pub fn new(content: &str) -> Result<Self> {
        let conf = Ini::load_from_str(content)?;

        let mut map: HashMap<_, _, _> = HashMap::default();

        for section in conf.sections() {
            // All profiles are stored in named section, we can ignore the
            // top level section.
            let section = if let Some(v) = section {
                v
            } else {
                continue;
            };

            let props = conf
                .section(Some(section))
                .expect("section is listed but not found, must be a bug of rust-init");

            let mut profile = CredentialProfile::default();
            if let Some(v) = props.get("aws_access_key_id") {
                profile.aws_access_key_id = Some(v.to_string())
            }
            if let Some(v) = props.get("aws_secret_access_key") {
                profile.aws_secret_access_key = Some(v.to_string())
            }
            if let Some(v) = props.get("aws_session_token") {
                profile.aws_session_token = Some(v.to_string())
            }

            // Credentials file's section does't have `profile` prefix.
            map.insert(section.to_string(), Arc::new(profile));
        }

        Ok(CredentialProfiles { map })
    }

    /// Get profile with given profile name.
    ///
    /// Return default value if not exist.
    pub fn get(&self, profile: &str) -> Arc<CredentialProfile> {
        self.map.get(profile).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_config_iam_identity_center() -> Result<()> {
        let content = r#"
[default]
sso_start_url = https://my-sso-portal.awsapps.com/start
sso_region = us-east-1
sso_account_id = 111122223333
sso_role_name = readOnly
region = us-west-2
output = text

[profile user1]
sso_start_url = https://my-sso-portal.awsapps.com/start
sso_region = us-east-1
sso_account_id = 444455556666
sso_role_name = readOnly
region = us-east-1
output = json
"#;

        let cfg = ConfigProfiles::new(content)?;

        assert_eq!(
            cfg.get("default"),
            ConfigProfile {
                sso_start_url: Some("https://my-sso-portal.awsapps.com/start".to_string()),
                sso_region: Some("us-east-1".to_string()),
                sso_account_id: Some("111122223333".to_string()),
                sso_role_name: Some("readOnly".to_string()),
                region: Some("us-west-2".to_string()),
                ..Default::default()
            }
            .into()
        );

        assert_eq!(
            cfg.get("user1"),
            ConfigProfile {
                sso_start_url: Some("https://my-sso-portal.awsapps.com/start".to_string()),
                sso_region: Some("us-east-1".to_string()),
                sso_account_id: Some("444455556666".to_string()),
                sso_role_name: Some("readOnly".to_string()),
                region: Some("us-east-1".to_string()),
                ..Default::default()
            }
            .into()
        );

        Ok(())
    }

    #[test]
    fn test_config_short_term_credentials() -> Result<()> {
        let content = r#"
[default]
region=us-west-2
output=json

[profile user1]
region=us-east-1
output=text
"#;

        let cfg = ConfigProfiles::new(content)?;

        assert_eq!(
            cfg.get("default"),
            ConfigProfile {
                region: Some("us-west-2".to_string()),
                ..Default::default()
            }
            .into()
        );

        assert_eq!(
            cfg.get("user1"),
            ConfigProfile {
                region: Some("us-east-1".to_string()),
                ..Default::default()
            }
            .into()
        );

        Ok(())
    }

    #[test]
    fn test_config_iam_role() -> Result<()> {
        let content = r#"
[default]
region=us-west-2
output=json

[profile user1]
role_arn=arn:aws:iam::777788889999:role/user1role
source_profile=default
role_session_name=session_user1
region=us-east-1
output=text
"#;

        let cfg = ConfigProfiles::new(content)?;

        assert_eq!(
            cfg.get("default"),
            ConfigProfile {
                region: Some("us-west-2".to_string()),
                ..Default::default()
            }
            .into()
        );

        assert_eq!(
            cfg.get("user1"),
            ConfigProfile {
                role_arn: Some("arn:aws:iam::777788889999:role/user1role".to_string()),
                source_profile: Some("default".to_string()),
                role_session_name: Some("session_user1".to_string()),
                region: Some("us-east-1".to_string()),
                ..Default::default()
            }
            .into()
        );

        Ok(())
    }

    #[test]
    fn test_config_amazon_ec2_instance_metadata() -> Result<()> {
        let content = r#"
[default]
role_arn=arn:aws:iam::123456789012:role/defaultrole
credential_source=Ec2InstanceMetadata
region=us-west-2
output=json

[profile user1]
role_arn=arn:aws:iam::777788889999:role/user1role
credential_source=Ec2InstanceMetadata
region=us-east-1
output=text
"#;

        let cfg = ConfigProfiles::new(content)?;

        assert_eq!(
            cfg.get("default"),
            ConfigProfile {
                role_arn: Some("arn:aws:iam::123456789012:role/defaultrole".to_string()),
                credential_source: Some("Ec2InstanceMetadata".to_string()),
                region: Some("us-west-2".to_string()),
                ..Default::default()
            }
            .into()
        );

        assert_eq!(
            cfg.get("user1"),
            ConfigProfile {
                role_arn: Some("arn:aws:iam::777788889999:role/user1role".to_string()),
                credential_source: Some("Ec2InstanceMetadata".to_string()),
                region: Some("us-east-1".to_string()),
                ..Default::default()
            }
            .into()
        );

        Ok(())
    }

    #[test]
    fn test_credential_short_term_credentials() -> Result<()> {
        let content = r#"
[default]
aws_access_key_id=AKIAIOSFODNN7EXAMPLE
aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws_session_token = IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZVERYLONGSTRINGEXAMPLE

[user1]
aws_access_key_id=AKIAI44QH8DHBEXAMPLE
aws_secret_access_key=je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
aws_session_token = fcZib3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZVERYLONGSTRINGEXAMPLE
"#;

        let cfg = CredentialProfiles::new(content)?;

        assert_eq!(
            cfg.get("default"),
            CredentialProfile {
                aws_access_key_id: Some("AKIAIOSFODNN7EXAMPLE".to_string()),
                aws_secret_access_key: Some("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string()),
                aws_session_token: Some("IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZVERYLONGSTRINGEXAMPLE".to_string()),
            }.into()
        );

        assert_eq!(
            cfg.get("user1"),
            CredentialProfile {
                aws_access_key_id: Some("AKIAI44QH8DHBEXAMPLE".to_string()),
                aws_secret_access_key: Some("je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY".to_string()),
                aws_session_token: Some("fcZib3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZVERYLONGSTRINGEXAMPLE".to_string()),
            }.into()
        );

        Ok(())
    }
}

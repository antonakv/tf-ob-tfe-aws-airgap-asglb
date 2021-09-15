#!/usr/bin/env bash
mkdir -p /home/ubuntu/install
echo "
{
    \"aws_access_key_id\": {},
    \"aws_instance_profile\": {
        \"value\": \"1\"
    },
    \"aws_secret_access_key\": {},
    \"azure_account_key\": {},
    \"azure_account_name\": {},
    \"azure_container\": {},
    \"azure_endpoint\": {},
    \"backup_token\": {
        \"value\": \"3e69c0572c1eddf7f232cf60f6b8634194bf40d09aa9535c78430e64df407ec4\"
    },
    \"ca_certs\": {},
    \"capacity_concurrency\": {
        \"value\": \"10\"
    },
    \"capacity_memory\": {
        \"value\": \"512\"
    },
    \"custom_image_tag\": {
        \"value\": \"hashicorp/build-worker:now\"
    },
    \"disk_path\": {},
    \"enable_active_active\": {
        \"value\": \"0\"
    },
    \"enable_metrics_collection\": {
        \"value\": \"1\"
    },
    \"enc_password\": {
        \"value\": \"${enc_password}\"
    },
    \"extern_vault_addr\": {},
    \"extern_vault_enable\": {
        \"value\": \"0\"
    },
    \"extern_vault_path\": {},
    \"extern_vault_propagate\": {},
    \"extern_vault_role_id\": {},
    \"extern_vault_secret_id\": {},
    \"extern_vault_token_renew\": {},
    \"extra_no_proxy\": {},
    \"force_tls\": {
        \"value\": \"0\"
    },
    \"gcs_bucket\": {},
    \"gcs_credentials\": {
        \"value\": \"{}\"
    },
    \"gcs_project\": {},
    \"hairpin_addressing\": {
        \"value\": \"0\"
    },
    \"hostname\": {
        \"value\": \"${hostname}\"
    },
    \"iact_subnet_list\": {},
    \"iact_subnet_time_limit\": {
        \"value\": \"60\"
    },
    \"installation_type\": {
        \"value\": \"production\"
    },
    \"pg_dbname\": {
        \"value\": \"mydbtfe\"
    },
    \"pg_extra_params\": {
        \"value\": \"sslmode=disable\"
    },
    \"pg_netloc\": {
        \"value\": \"${pgsqlhostname}\"
    },
    \"pg_password\": {
        \"value\": \"${pgsqlpassword}\"
    },
    \"pg_user\": {
        \"value\": \"${pguser}\"
    },
    \"placement\": {
        \"value\": \"placement_s3\"
    },
    \"production_type\": {
        \"value\": \"external\"
    },
    \"redis_host\": {},
    \"redis_pass\": {
        \"value\": \"NGVITSiZJKkmtC9ed1XWjScsVZMnXJx5\"
    },
    \"redis_port\": {},
    \"redis_use_password_auth\": {},
    \"redis_use_tls\": {},
    \"restrict_worker_metadata_access\": {
        \"value\": \"0\"
    },
    \"s3_bucket\": {
        \"value\": \"${s3bucket}\"
    },
    \"s3_endpoint\": {},
    \"s3_region\": {
        \"value\": \"${s3region}\"
    },
    \"s3_sse\": {},
    \"s3_sse_kms_key_id\": {},
    \"tbw_image\": {
        \"value\": \"default_image\"
    },
    \"tls_ciphers\": {},
    \"tls_vers\": {
        \"value\": \"tls_1_2_tls_1_3\"
    }
}
" > /home/ubuntu/install/settings.json

echo "
{
    \"DaemonAuthenticationType\":     \"password\",
    \"DaemonAuthenticationPassword\": \"Password1#\",
    \"TlsBootstrapType\":             \"server-path\",
    \"TlsBootstrapHostname\":         \"${hostname}\",
    \"TlsBootstrapCert\":             \"/home/ubuntu/install/server.crt\",
    \"TlsBootstrapKey\":              \"/home/ubuntu/install/server.key\",
    \"BypassPreflightChecks\":        true,
    \"ImportSettingsFrom\":           \"/home/ubuntu/install/settings.json\",
    \"LicenseFileLocation\":          \"/home/ubuntu/install/license.rli\",
    \"LicenseBootstrapAirgapPackagePath\": \"/home/ubuntu/install/tfe-557.airgap\"
}" > /home/ubuntu/install/replicated.conf
echo "${cert_pem}" > /home/ubuntu/install/server.crt
echo "${key_pem}" > /home/ubuntu/install/server.key
IPADDR=$(hostname -I | awk '{print $1}')
echo "#!/usr/bin/env bash
chmod 600 /home/ubuntu/install/server.key
cd /home/ubuntu/install
aws s3 cp s3://aakulov-aws4-tfe-airgap . --recursive
tar -xf latest.tar.gz
sudo rm -rf /usr/share/keyrings/docker-archive-keyring.gpg
cp /home/ubuntu/install/replicated.conf /etc/replicated.conf
cp /home/ubuntu/install/replicated.conf /root/replicated.conf
chown -R ubuntu: /home/ubuntu/install
yes | sudo ./install.sh airgap no-proxy private-address=$IPADDR public-address=$IPADDR" > /home/ubuntu/install/install_tfe.sh

chmod +x /home/ubuntu/install/install_tfe.sh

sh /home/ubuntu/install/install_tfe.sh &> /home/ubuntu/install/install_tfe.log

use clap::{Parser, Subcommand};
use sops_secrets::shared::logging;
use sops_secrets::sops::{SopsConfig, SopsError, SopsResult, SopsWrapper, SecretData};
use std::collections::HashMap;
use std::time::Duration;
use serde_json;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about = "SOPS Secrets Manager CLI", long_about = None)]
struct Args {
    /// Path to the SOPS file
    #[arg(short, long, default_value = "secrets.json")]
    file: PathBuf,

    /// Path to the master key file
    #[arg(short, long)]
    master_key: PathBuf,

    /// Path to the SOPS executable
    #[arg(long, default_value = "/usr/local/bin/sops")]
    sops_path: PathBuf,

    /// Timeout for operations in seconds
    #[arg(long, default_value = "30")]
    timeout: u64,

    /// Command to execute
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize a new SOPS file
    Init {
        /// Initial secrets to add (key=value pairs)
        #[arg(short, long)]
        secrets: Vec<String>,

        /// Owner of the secrets
        #[arg(short, long)]
        owner: String,
    },

    /// Get a secret value
    Get {
        /// Secret key
        #[arg(short, long)]
        key: String,
    },

    /// Add an owned secret with access control
    AddOwned {
        /// Owner name
        #[arg(short, long)]
        owner: String,

        /// Secret name
        #[arg(short, long)]
        name: String,

        /// Secret value
        #[arg(short, long)]
        value: String,

        /// Allowed readers (comma-separated)
        #[arg(long)]
        readers: Option<String>,

        /// Allowed writers (comma-separated)
        #[arg(long)]
        writers: Option<String>,
    },

    /// Update a secret value
    Update {
        /// Secret name
        #[arg(short, long)]
        name: String,

        /// New secret value
        #[arg(short, long)]
        value: String,
    },

    /// Manage access control for secrets
    Access {
        /// Subcommand for access control
        #[command(subcommand)]
        subcommand: AccessCommands,
    },

    /// Validate SOPS installation and configuration
    Validate,

    /// Show secret metadata and access control information
    Info {
        /// Secret name
        #[arg(short, long)]
        name: String,
    },
}

#[derive(Subcommand, Debug)]
enum AccessCommands {
    /// Get readers for a secret
    GetReaders {
        /// Secret name
        #[arg(short, long)]
        secret: String,
    },

    /// Get writers for a secret
    GetWriters {
        /// Secret name
        #[arg(short, long)]
        secret: String,
    },

    /// Add a reader to a secret
    AddReader {
        /// Secret name
        #[arg(short, long)]
        secret: String,

        /// Reader name
        #[arg(short, long)]
        reader: String,
    },

    /// Remove a reader from a secret
    RemoveReader {
        /// Secret name
        #[arg(short, long)]
        secret: String,

        /// Reader name
        #[arg(short, long)]
        reader: String,
    },

    /// Add a writer to a secret
    AddWriter {
        /// Secret name
        #[arg(short, long)]
        secret: String,

        /// Writer name
        #[arg(short, long)]
        writer: String,
    },

    /// Remove a writer from a secret
    RemoveWriter {
        /// Secret name
        #[arg(short, long)]
        secret: String,

        /// Writer name
        #[arg(short, long)]
        writer: String,
    },
    /// Check if a user can read a secret
    CanRead {
        /// Secret name
        #[arg(short, long)]
        secret: String,

        /// User name
        #[arg(short, long)]
        user: String,
    },

    /// Check if a user can write a secret
    CanWrite {
        /// Secret name
        #[arg(short, long)]
        secret: String,

        /// User name
        #[arg(short, long)]
        user: String,
    },
}

#[tokio::main]
async fn main() {
    // Initialize the custom logger
    logging::init_logger();

    let args = Args::parse();

    let config = SopsConfig::with_sops_path(args.file, args.master_key, args.sops_path)
        .with_timeout(Duration::from_secs(args.timeout));

    let mut sops = SopsWrapper::with_config(config);

    if let Err(e) = handle_commands(&mut sops, &args.command).await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

async fn handle_commands(sops: &mut SopsWrapper, command: &Commands) -> SopsResult<()> {
    match command {
        Commands::Init { secrets, owner } => {
            println!("Initializing SOPS file with {} secrets for owner '{}'...", secrets.len(), owner);
            
            let mut secrets_map = HashMap::new();
            
            for secret_pair in secrets {
                let parts: Vec<&str> = secret_pair.splitn(2, '=').collect();
                if parts.len() != 2 {
                    return Err(SopsError::InvalidSecretInput(
                        format!("Invalid secret format: {}. Expected key=value", secret_pair)
                    ));
                }
                let key = parts[0];
                let value = parts[1];
                
                let secret_data = SecretData::new(
                    value.to_string(),
                    owner.to_string(),
                    Some(vec![]),
                    Some(vec![])
                );
                secrets_map.insert(key.to_string(), secret_data);
            }
            
            sops.update_secrets(&secrets_map, None).await?;
            println!("✅ SOPS file initialized successfully with {} secrets", secrets.len());
        }
        Commands::Get { key } => {
            println!("Retrieving secret '{}'...", key);
            let secret_data = sops.get_secret_data_for_key(key, None, None).await?;
            println!("{}", secret_data.get_value());
        }
        Commands::AddOwned { owner, name, value, readers, writers } => {
            println!("Adding owned secret '{}' for owner '{}'...", name, owner);

            let readers_vec: Vec<String> = readers.as_ref()
                .map(|r| r.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default();

            let writers_vec: Vec<String> = writers.as_ref()
                .map(|w| w.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default();

            let secret = if sops.key_exists(name, None, None).await? {
                let mut secret_data = sops.get_secret_data_for_key(name, None, None).await?;

                for x in readers_vec {
                    secret_data.add_reader(x);
                }
                for x in writers_vec {
                    secret_data.add_writer(x);
                }

                secret_data
            }
            else {
                SecretData::new(value.to_string(), owner.to_string(), Some(readers_vec), Some(writers_vec))
            };

            let secrets_to_add = create_secrets_map(name, secret);
            
            sops.update_secrets(&secrets_to_add, None).await?;
            println!("✅ Owned secret '{}' added successfully", name);
        }
        Commands::Update { name, value } => {
            println!("Updating secret '{}'...", name);

            let mut secret_data = if sops.key_exists(name, None, None).await? {
                sops.get_secret_data_for_key(name, None, None).await?
            }
            else {
                eprintln!("Secret '{}' does not exist", name);
                return Err(SopsError::NoSecretFound);
            };

            secret_data.set_value(value.to_string());
            
            let secrets_to_update = create_secrets_map(name, secret_data);
            
            sops.update_secrets(&secrets_to_update, None).await?;
            println!("✅ Secret '{}' updated successfully", name);
        }
        Commands::Access { subcommand } => {
            handle_access_commands(sops, subcommand).await?;
        }
        Commands::Validate => {
            println!("Validating SOPS installation...");
            sops.validate_sops(None).await?;
            println!("✅ SOPS validation successful");
        }
        Commands::Info { name } => {
            println!("Getting info for secret '{}'...", name);
            let secret_data = sops.get_secret_data_for_key(name, None, None).await?;
            println!("Secret: {}", name);
            println!("Owner: {}", secret_data.owner);
            println!("Readers: {}", secret_data.readers.join(", "));
            println!("Writers: {}", secret_data.writers.join(", "));
        }
    }
    Ok(())
}

/// Helper function to create a secrets map with a single entry, avoiding unnecessary cloning
fn create_secrets_map(name: &str, secret_data: SecretData) -> HashMap<String, SecretData> {
    let mut map = HashMap::new();
    map.insert(name.to_string(), secret_data);
    map
}

async fn handle_access_commands(sops: &mut SopsWrapper, command: &AccessCommands) -> SopsResult<()> {
    match command {
        AccessCommands::GetReaders { secret } => {
            println!("Getting readers for secret '{}'...", secret);
            let secret_data = sops.get_secret_data_for_key(secret, None, None).await?;
            println!("Readers: {}", secret_data.readers.join(", "));
        }
        AccessCommands::GetWriters { secret } => {
            println!("Getting writers for secret '{}'...", secret);
            let secret_data = sops.get_secret_data_for_key(secret, None, None).await?;
            println!("Writers: {}", secret_data.writers.join(", "));
        }
        AccessCommands::AddReader { secret: name, reader } => {
            println!("Adding reader '{}' to secret '{}'...", reader, name);

            let mut secret_data = if sops.key_exists(name, None, None).await? {
                sops.get_secret_data_for_key(name, None, None).await?
            }
            else {
                eprintln!("Secret '{}' does not exist", name);
                return Err(SopsError::NoSecretFound)?
            };

            secret_data.add_reader(reader.to_string());

            let secrets_to_update = create_secrets_map(name, secret_data);

            sops.update_secrets(&secrets_to_update, None).await?;
            println!("✅ Reader '{}' added successfully", reader);
        }
        AccessCommands::RemoveReader { secret: name, reader } => {
            println!("Removing reader '{}' from secret '{}'...", reader, name);

            let mut secret_data = if sops.key_exists(name, None, None).await? {
                sops.get_secret_data_for_key(name, None, None).await?
            }
            else {
                eprintln!("Secret '{}' does not exist", name);
                return Err(SopsError::NoSecretFound)?
            };

            secret_data.remove_reader(reader);

            let secrets_to_update = create_secrets_map(name, secret_data);

            sops.update_secrets(&secrets_to_update, None).await?;

            println!("✅ Reader '{}' removed successfully", reader);
        }
        AccessCommands::AddWriter { secret: name, writer } => {
            println!("Adding writer '{}' to secret '{}'...", writer, name);

            let mut secret_data = if sops.key_exists(name, None, None).await? {
                sops.get_secret_data_for_key(name, None, None).await?
            }
            else {
                eprintln!("Secret '{}' does not exist", name);
                return Err(SopsError::NoSecretFound)?
            };

            secret_data.add_writer(writer.to_string());

            let secrets_to_update = create_secrets_map(name, secret_data);

            sops.update_secrets(&secrets_to_update, None).await?;
            println!("✅ Writer '{}' added successfully", writer);
        }
        AccessCommands::RemoveWriter { secret: name, writer } => {
            println!("Removing writer '{}' from secret '{}'...", writer, name);

            let mut secret_data = if sops.key_exists(name, None, None).await? {
                sops.get_secret_data_for_key(name, None, None).await?
            }
            else {
                eprintln!("Secret '{}' does not exist", name);
                return Err(SopsError::NoSecretFound)?
            };

            secret_data.remove_writer(writer);

            let secrets_to_update = create_secrets_map(name, secret_data);

            sops.update_secrets(&secrets_to_update, None).await?;
            println!("✅ Writer '{}' removed successfully", writer);
        }
        AccessCommands::CanRead { secret: name, user } => {
            let mut secret_data = if sops.key_exists(name, None, None).await? {
                sops.get_secret_data_for_key(name, None, None).await?
            }
            else {
                eprintln!("Secret '{}' does not exist", name);
                return Err(SopsError::NoSecretFound)?
            };

            let can_read = secret_data.can_read(user);
            println!("User '{}' can read '{}': {}", user, name, can_read);
        }
        AccessCommands::CanWrite { secret: name, user } => {
            let mut secret_data = if sops.key_exists(name, None, None).await? {
                sops.get_secret_data_for_key(name, None, None).await?
            }
            else {
                eprintln!("Secret '{}' does not exist", name);
                return Err(SopsError::NoSecretFound)?
            };

            let can_write = secret_data.can_write(user);
            println!("User '{}' can write '{}': {}", user, name, can_write);
        }
    }

    Ok(())
}

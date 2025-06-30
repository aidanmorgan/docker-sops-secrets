use clap::{Parser, Subcommand};
use sops_secrets::shared::{SopsWrapper, SopsConfig, SopsResult};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(author, version, about = "SOPS Secrets Manager CLI", long_about = None)]
struct Args {
    /// Path to the SOPS file
    #[arg(short, long, default_value = "secrets.yaml")]
    file: String,

    /// Path to the master key file
    #[arg(short, long)]
    master_key: String,

    /// Path to the SOPS executable
    #[arg(long, default_value = "/usr/local/bin/sops")]
    sops_path: String,

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

    /// Get an owned secret
    GetOwned {
        /// Owner name
        #[arg(short, long)]
        owner: String,

        /// Secret name
        #[arg(short, long)]
        name: String,
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
    let args = Args::parse();
    
    let config = SopsConfig {
        sops_path: args.sops_path,
        file_path: args.file,
        master_key_path: args.master_key,
        default_timeout: Duration::from_secs(args.timeout),
        ..Default::default()
    };

    let sops = SopsWrapper::with_config(config);
    
    if let Err(e) = handle_commands(&sops, &args.command).await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

async fn handle_commands(sops: &SopsWrapper, command: &Commands) -> SopsResult<()> {
    match command {
        Commands::Init { secrets, owner } => {
            println!("Initializing new SOPS file...");
            
            let mut secrets_map = HashMap::new();
            for secret_pair in secrets {
                if let Some((key, value)) = secret_pair.split_once('=') {
                    secrets_map.insert(key.to_string(), value.to_string());
                } else {
                    return Err(sops_secrets::shared::SopsError::InvalidSecretFormat(
                        format!("Invalid secret format: {}", secret_pair)
                    ));
                }
            }
            
            sops.create_file(owner, &secrets_map, None).await?;
            println!("✅ SOPS file initialized successfully");
        }

        Commands::Get { key } => {
            println!("Retrieving secret '{}'...", key);
            let value = sops.get_secret(key, None).await?;
            println!("{}", value);
        }

        Commands::AddOwned { owner, name, value, readers, writers } => {
            println!("Adding owned secret '{}' for owner '{}'...", name, owner);
            
            let readers_vec = readers
                .as_ref()
                .map(|r| r.split(',').map(|s| s.trim().to_string()).collect::<Vec<_>>())
                .unwrap_or_default();
            
            let writers_vec = writers
                .as_ref()
                .map(|w| w.split(',').map(|s| s.trim().to_string()).collect::<Vec<_>>())
                .unwrap_or_default();
            
            sops.add_owned_secret(owner, name, value, &readers_vec, &writers_vec, None).await?;
            println!("✅ Owned secret '{}' added successfully", name);
        }

        Commands::GetOwned { owner, name } => {
            println!("Retrieving owned secret '{}' for owner '{}'...", name, owner);
            let value = sops.get_owned_secret(owner, name, None).await?;
            println!("{}", value);
        }

        Commands::Update { name, value } => {
            println!("Updating secret '{}'...", name);
            sops.update_secret_value(name, value, None).await?;
            println!("✅ Secret '{}' updated successfully", name);
        }

        Commands::Access { subcommand } => {
            handle_access_commands(sops, subcommand).await?;
        }

        Commands::Validate => {
            println!("Validating SOPS installation and configuration...");
            sops.validate_sops(None).await?;
            println!("✅ SOPS validation successful");
        }

        Commands::Info { name } => {
            println!("Getting info for secret '{}'...", name);
            let secret_data = sops.get_secret_data(name, None).await?;
            
            println!("Secret: {}", name);
            println!("Owner: {}", secret_data.owner);
            println!("Readers: {}", secret_data.readers.join(", "));
            println!("Writers: {}", secret_data.writers.join(", "));
        }
    }
    
    Ok(())
}

async fn handle_access_commands(sops: &SopsWrapper, command: &AccessCommands) -> SopsResult<()> {
    match command {
        AccessCommands::GetReaders { secret } => {
            let readers = sops.get_secret_readers(secret, None).await?;
            println!("Readers for '{}': {}", secret, readers.join(", "));
        }

        AccessCommands::GetWriters { secret } => {
            let writers = sops.get_secret_writers(secret, None).await?;
            println!("Writers for '{}': {}", secret, writers.join(", "));
        }

        AccessCommands::AddReader { secret, reader } => {
            println!("Adding reader '{}' to secret '{}'...", reader, secret);
            sops.add_reader_to_secret(secret, reader, None).await?;
            println!("✅ Reader '{}' added successfully", reader);
        }

        AccessCommands::RemoveReader { secret, reader } => {
            println!("Removing reader '{}' from secret '{}'...", reader, secret);
            sops.remove_reader_from_secret(secret, reader, None).await?;
            println!("✅ Reader '{}' removed successfully", reader);
        }

        AccessCommands::AddWriter { secret, writer } => {
            println!("Adding writer '{}' to secret '{}'...", writer, secret);
            sops.add_writer_to_secret(secret, writer, None).await?;
            println!("✅ Writer '{}' added successfully", writer);
        }

        AccessCommands::RemoveWriter { secret, writer } => {
            println!("Removing writer '{}' from secret '{}'...", writer, secret);
            sops.remove_writer_from_secret(secret, writer, None).await?;
            println!("✅ Writer '{}' removed successfully", writer);
        }

        AccessCommands::CanRead { secret, user } => {
            let can_read = sops.is_allowed_to_read("", secret, user, None).await?;
            println!("User '{}' can read '{}': {}", user, secret, can_read);
        }

        AccessCommands::CanWrite { secret, user } => {
            let can_write = sops.is_writer_allowed_to_write(secret, user, None).await?;
            println!("User '{}' can write '{}': {}", user, secret, can_write);
        }
    }
    
    Ok(())
}

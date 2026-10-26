//! `ghost-gate-admin` — the administrator control plane binary.
//!
//! What it does at startup, in order:
//! 1. Read or create the data directory (registry, bindings, sessions, audit log).
//! 2. If no administrator credential exists yet, create a bootstrap token: printed ONCE to stdout
//!    and written 0600 to `bootstrap.token`. The first registration must present it; after that
//!    the token is void and registration is closed.
//! 3. Serve the dashboard and the API on the configured loopback address.
//!
//! Security posture: the control plane binds loopback by default. It is the ONLY writer of the
//! registry; the bridge consumes the derived bindings snapshot read-only.

use ghost_gate_admin::server::{serve, AdminState, Response};
use ghost_gate_registry::{load_registry, StorePaths, StoreLock};
use std::fs;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

fn main() -> ExitCode {
    let data_dir = std::env::var("GG_ADMIN_DATA").unwrap_or_else(|_| "gg-admin-data".into());
    let bind = std::env::var("GG_ADMIN_BIND").unwrap_or_else(|_| "127.0.0.1:7811".into());
    // The public hostname, which is NOT always the bind address: a passkey ceremony fails outright
    // on an IP address, because WebAuthn requires a registrable domain as the RP ID. Binding stays
    // on loopback (the admin plane is never exposed), while the origin an operator opens can be
    // `localhost` — which browsers accept — or a real domain.
    let hostname = std::env::var("GG_ADMIN_HOSTNAME")
        .ok()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| bind.split(':').next().unwrap_or("127.0.0.1").to_string());
    let port = bind.rsplit(':').next().unwrap_or("7811");
    let origin = format!("http://{}:{}", hostname, port);
    // rpId for WebAuthn: the host part of the public origin, which must not be an IP literal.
    let rp_id = hostname.clone();
    let ip_literal = hostname.parse::<std::net::IpAddr>().is_ok();

    let paths = StorePaths::new(&data_dir);
    if let Err(e) = fs::create_dir_all(&paths.dir) {
        eprintln!("ghost-gate-admin: cannot create the data directory {data_dir:?}: {e}");
        return ExitCode::FAILURE;
    }

    // Refuse to start on a corrupt registry: fail closed, keep the operator's file untouched.
    if let Err(e) = load_registry(&paths) {
        eprintln!("ghost-gate-admin: {e}");
        eprintln!("ghost-gate-admin: refusing to start on an invalid registry. Fix or restore registry.json first.");
        return ExitCode::FAILURE;
    }

    // Bootstrap token: only meaningful while no administrator credential exists.
    let reg = load_registry(&paths).unwrap_or_default();
    let bootstrap_token = if reg.credentials.is_empty() {
        let token = {
            let mut b = [0u8; 24];
            rand::fill(&mut b);
            hex::encode(b)
        };
        match write_bootstrap(&paths, &token) {
            Ok(()) => {
                println!("  ==========================================================");
                println!("  FIRST-RUN BOOTSTRAP TOKEN (required to register the first");
                println!("  administrator; void once one exists):");
                println!();
                println!("      {token}");
                println!();
                println!("  Also stored at {} (mode 0600).", paths.bootstrap().display());
                println!("  ==========================================================");
                Some(token)
            }
            Err(e) => {
                eprintln!("ghost-gate-admin: cannot write the bootstrap token: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };

    // A leftover bootstrap file from a previous run with admins already registered is void.
    if bootstrap_token.is_none() && paths.bootstrap().exists() {
        let _ = fs::remove_file(paths.bootstrap());
    }

    let state = Arc::new(AdminState {
        paths: paths.clone(),
        origin: origin.clone(),
        rp_id,
        pending: Mutex::new(std::collections::BTreeMap::new()),
        bootstrap_token: bootstrap_token.clone(),
        genesis_hash: std::env::var("GG_GENESIS_HASH").ok().map(|g| g.trim().to_string()).filter(|g| !g.is_empty()),
        chain_generation: std::env::var("GG_CHAIN_GENERATION").ok().and_then(|g| g.trim().parse::<u64>().ok()).filter(|g| *g > 0),
    });

    println!("ghost-gate-admin listening on {origin}");
    println!("  dashboard: {origin}/admin");
    if ip_literal {
        // Say it at startup rather than letting the operator meet a browser SecurityError later.
        println!(
            "  note: the public hostname is an IP address, so PASSKEYS CANNOT WORK HERE — WebAuthn \
             requires a registrable domain as the RP ID. Start with GG_ADMIN_HOSTNAME=localhost (or a \
             real domain) and open http://{hostname}:{port}/admin, or use the wallet-key method."
        );
    }
    println!("  data dir:  {}", paths.dir.display());
    if bootstrap_token.is_some() {
        println!("  registration: OPEN (first administrator only, bootstrap token required)");
    } else {
        println!("  registration: CLOSED (an administrator already exists)");
    }
    match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => match rt.block_on(serve(state, &bind)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("ghost-gate-admin: {e}");
                ExitCode::FAILURE
            }
        },
        Err(e) => {
            eprintln!("ghost-gate-admin: could not start a runtime: {e}");
            ExitCode::FAILURE
        }
    }
}

fn write_bootstrap(paths: &StorePaths, token: &str) -> Result<(), String> {
    use std::io::Write;
    let _lock = StoreLock::acquire(paths)?;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(paths.bootstrap())
        .map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
    }
    f.write_all(token.as_bytes()).and_then(|_| f.flush()).map_err(|e| e.to_string())
}

/// Keep the compiler honest about Response being used in this binary's error paths.
#[allow(dead_code)]
fn _type_witness() -> Response {
    Response::error(500, "unreachable")
}

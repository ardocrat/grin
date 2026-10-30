// Copyright 2026 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::tor::arti::{start_tor_client, start_tor_service};
use crate::tor::config::TorConfig;
use crate::tor::process::types::TorProcess;

use ed25519_dalek::hazmat::ExpandedSecretKey;
use grin_util::secp::SecretKey;
use hyper::StatusCode;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
	/// Generic Tor error
	#[error("Tor Process Error: {0}")]
	Generic(String),
	/// Tor configuration error
	#[error("Tor Config Error: {0}")]
	Config(String),
	/// POST HTTP request error.
	#[error("Tor POST Error: {0}")]
	Post(PostError),
}

/// Failure from a POST HTTP request over Tor, classified by whether delivery may
/// have started.
#[derive(Debug, thiserror::Error)]
pub enum PostError {
	/// The failure happened before handing the request to Hyper.
	#[error("Not sent: {0}")]
	NotSent(String),
	/// Hyper started sending the request, so delivery cannot be ruled out.
	#[error("Possibly sent: {0}")]
	PossiblySent(String, Option<StatusCode>, Option<String>),
}

/// Convert expanded secret key to byte array (works for both external Tor process and Arti).
pub(crate) fn exp_sec_key_bytes(expanded_sk: ExpandedSecretKey) -> [u8; 64] {
	let mut sk_bytes = [0_u8; 64];
	sk_bytes[0..32].copy_from_slice(&expanded_sk.scalar.to_bytes());
	sk_bytes[32..64].copy_from_slice(&expanded_sk.hash_prefix);
	sk_bytes
}

/// Start integrated Tor client or external process to send. Integrated Tor will reuse same client.
pub fn start_tor<T>(config: &T) -> Result<Option<TorProcess>, Error>
where
	T: TorConfig,
{
	let tor = if config.use_integrated() {
		start_tor_client(config)?;
		None
	} else {
		let p = TorProcess::start_sender(config)?;
		Some(p)
	};
	Ok(tor)
}

/// Start Tor service from provided key to forward requests to
/// provided address and store listener data at provided dir for process.
pub fn start_onion_service<T>(
	sec_key: SecretKey,
	addr: &str,
	dir: PathBuf,
	config: &T,
) -> Result<Option<TorProcess>, Error>
where
	T: TorConfig,
{
	let res: Result<Option<TorProcess>, Error> = if config.use_integrated() {
		match start_tor_service(sec_key, addr, config) {
			Ok(_) => Ok(None),
			Err(e) => {
				error!("Error starting Tor service with integrated client: {}", e);
				Err(e)
			}
		}
	} else {
		match TorProcess::start_listener(sec_key, dir, addr, config) {
			Ok(p) => Ok(Some(p)),
			Err(e) => {
				error!("Error starting Tor service with external process: {}", e);
				Err(e)
			}
		}
	};
	res
}

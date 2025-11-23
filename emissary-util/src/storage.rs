// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use anyhow::anyhow;
use flate2::write::GzDecoder;
use home::home_dir;
use rand::RngCore;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary-util::storage";

/// Router profile.
#[derive(Debug, Serialize, Deserialize)]
pub struct Profile {
    last_activity: Option<u64>,
    last_declined: Option<u64>,
    last_dial_failure: Option<u64>,
    num_accepted: Option<usize>,
    num_connection: Option<usize>,
    num_dial_failures: Option<usize>,
    num_lookup_failures: Option<usize>,
    num_lookup_no_responses: Option<usize>,
    num_lookup_successes: Option<usize>,
    num_rejected: Option<usize>,
    num_selected: Option<usize>,
    num_test_failures: Option<usize>,
    num_test_successes: Option<usize>,
    num_unaswered: Option<usize>,
}

impl From<emissary_core::Profile> for Profile {
    fn from(profile: emissary_core::Profile) -> Self {
        Profile {
            last_activity: Some(profile.last_activity.as_secs()),
            last_declined: profile.last_declined.map(|last_declined| last_declined.as_secs()),
            last_dial_failure: profile
                .last_dial_failure
                .map(|last_dial_failure| last_dial_failure.as_secs()),
            num_accepted: Some(profile.num_accepted),
            num_connection: Some(profile.num_connection),
            num_dial_failures: Some(profile.num_dial_failures),
            num_lookup_failures: Some(profile.num_lookup_failures),
            num_lookup_no_responses: Some(profile.num_lookup_no_responses),
            num_lookup_successes: Some(profile.num_lookup_successes),
            num_rejected: Some(profile.num_rejected),
            num_selected: Some(profile.num_selected),
            num_test_failures: Some(profile.num_test_failures),
            num_test_successes: Some(profile.num_test_successes),
            num_unaswered: Some(profile.num_unaswered),
        }
    }
}

/// Storage bundle.
pub struct StorageBundle {
    /// NTCP2 IV.
    pub ntcp2_iv: [u8; 16],

    /// NTCP2 key.
    pub ntcp2_key: [u8; 32],

    /// Router profiles.
    pub profiles: Vec<(String, emissary_core::Profile)>,

    /// Local router info, if it was stored on disk.
    pub router_info: Option<Vec<u8>>,

    /// Router infos.
    pub routers: Vec<Vec<u8>>,

    /// Router signing key.
    pub signing_key: [u8; 32],

    /// Router static key.
    pub static_key: [u8; 32],

    /// SSU2 intro key.
    pub ssu2_intro_key: [u8; 32],

    /// SSU2 static key.
    pub ssu2_static_key: [u8; 32],
}

/// Storage for `emissary`.
#[derive(Clone)]
pub struct Storage {
    /// Base path.
    base_path: PathBuf,
}

impl Storage {
    /// Create new [`Storage`].
    pub async fn new(base_path: Option<PathBuf>) -> anyhow::Result<Self> {
        let base_path = base_path
            .map_or_else(
                || {
                    let mut path = home_dir()?;
                    (!path.as_os_str().is_empty()).then(|| {
                        path.push(".emissary");
                        path
                    })
                },
                Some,
            )
            .ok_or(anyhow!("failed to resolve base path"))?;

        if !base_path.exists() {
            tokio::fs::create_dir_all(&base_path).await?;
        }

        let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~";
        let netdb = base_path.join("netDb");
        let profiles = base_path.join("peerProfiles");

        // create directory for router infos if it doesn't exist yet
        if !netdb.exists() {
            tokio::fs::create_dir_all(&netdb).await?;

            for c in chars.chars() {
                tokio::fs::create_dir_all(netdb.join(format!("r{c}"))).await?;
            }
        }

        // create directory for router profiles if it doesn't exist yet
        if !profiles.exists() {
            tokio::fs::create_dir_all(&profiles).await?;

            for c in chars.chars() {
                tokio::fs::create_dir_all(profiles.join(format!("p{c}"))).await?;
            }
        }

        // create ntcp2 key and iv if they don't exist
        if !base_path.join("ntcp2.keys").exists() {
            let key = x25519_dalek::StaticSecret::random().to_bytes().to_vec();
            let iv = {
                let mut iv = [0u8; 16];
                rand_core::OsRng.fill_bytes(&mut iv);

                iv
            };

            let mut combined = vec![0u8; 32 + 16];
            combined[..32].copy_from_slice(&key);
            combined[32..].copy_from_slice(&iv);

            match tokio::fs::File::create(base_path.join("ntcp2.keys")).await {
                Ok(mut file) =>
                    if let Err(error) = file.write_all(combined.as_ref()).await {
                        tracing::error!(
                            target: LOG_TARGET,
                            error = ?error.kind(),
                            path = %base_path.join("ntcp2.keys").display(),
                            "failed to write ntcp2 keys to disk",
                        )
                    },
                Err(error) => tracing::error!(
                    target: LOG_TARGET,
                    error = ?error.kind(),
                    path = %base_path.join("ntcp2.keys").display(),
                    "failed to write ntcp2 keys to disk",
                ),
            }
        }

        // create ssu2 keys if they don't exist yet
        if !base_path.join("ssu2.keys").exists() {
            let static_key = x25519_dalek::StaticSecret::random().to_bytes().to_vec();
            let intro_key = {
                let mut intro_key = [0u8; 32];
                rand_core::OsRng.fill_bytes(&mut intro_key);

                intro_key
            };

            let mut combined = vec![0u8; 32 + 32];
            combined[..32].copy_from_slice(&static_key);
            combined[32..].copy_from_slice(&intro_key);

            match tokio::fs::File::create(base_path.join("ssu2.keys")).await {
                Ok(mut file) =>
                    if let Err(error) = file.write_all(combined.as_ref()).await {
                        tracing::error!(
                            target: LOG_TARGET,
                            error = ?error.kind(),
                            path = %base_path.join("ssu2.keys").display(),
                            "failed to write ssu2 keys to disk",
                        )
                    },
                Err(error) => tracing::error!(
                    target: LOG_TARGET,
                    error = ?error.kind(),
                    path = %base_path.join("ssu2.keys").display(),
                    "failed to write ssu2 keys to disk",
                ),
            }
        }

        // create router static key if it doesn't exist yet
        if !base_path.join("static.key").exists() {
            let key = x25519_dalek::StaticSecret::random();
            tokio::fs::write(base_path.join("static.key"), key).await?;
        }

        if !base_path.join("signing.key").exists() {
            let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
            tokio::fs::write(base_path.join("signing.key"), key.as_bytes()).await?;
        }

        Ok(Self { base_path })
    }

    /// Get base path.
    pub fn base_path(&self) -> PathBuf {
        self.base_path.clone()
    }

    /// Load router infos and peer profiles from disk.
    ///
    /// Returns a tuple of vectors where the first element of the tuple is a vector of serialized
    /// `routerInfo`s and the second element of the tuple is a vector of (router id, profile)
    /// tuples.
    pub async fn load(&self) -> StorageBundle {
        let netdb_path = self.base_path.join("netDb");
        let profiles_path = self.base_path.join("peerProfiles");

        let router_infos = tokio::task::spawn_blocking(move || Self::load_router_infos(netdb_path));
        let router_profiles =
            tokio::task::spawn_blocking(move || Self::load_router_profiles(profiles_path));

        let (routers, profiles) = match tokio::join!(router_infos, router_profiles) {
            (Ok(router_infos), Ok(router_profiles)) => (router_infos, router_profiles),
            _ => (vec![], vec![]),
        };

        let (ntcp2_key, ntcp2_iv) = {
            // `Storage::new()` created ntcp2 key and iv if they didn't exist
            let key_bytes = tokio::fs::read(self.base_path.join("ntcp2.keys"))
                .await
                .expect("ntcp2 keys to exist");

            (
                TryInto::<[u8; 32]>::try_into(&key_bytes[..32]).expect("to succeed"),
                TryInto::<[u8; 16]>::try_into(&key_bytes[32..]).expect("to succeed"),
            )
        };

        let (ssu2_static_key, ssu2_intro_key) = {
            // `Storage::new()` created ssu2 keys if they didn't exist
            let key_bytes = tokio::fs::read(self.base_path.join("ssu2.keys"))
                .await
                .expect("ssu2.keys to exist");

            (
                TryInto::<[u8; 32]>::try_into(&key_bytes[..32]).expect("to succeed"),
                TryInto::<[u8; 32]>::try_into(&key_bytes[32..]).expect("to succeed"),
            )
        };

        let static_key = {
            // `Storage::new()` created the static key if it didn't exist
            let key_bytes = tokio::fs::read(self.base_path.join("static.key"))
                .await
                .expect("static.key to exist");

            TryInto::<[u8; 32]>::try_into(&key_bytes[..]).expect("to succeed")
        };

        let signing_key = {
            // `Storage::new()` created the signing key if it didn't exist
            let key_bytes = tokio::fs::read(self.base_path.join("signing.key"))
                .await
                .expect("signing.key to exist");

            TryInto::<[u8; 32]>::try_into(&key_bytes[..]).expect("to succeed")
        };

        // attempt to load local router info
        let router_info = tokio::fs::read(self.base_path.join("router.info")).await.ok();

        StorageBundle {
            ntcp2_iv,
            ntcp2_key,
            profiles,
            router_info,
            routers,
            signing_key,
            ssu2_intro_key,
            ssu2_static_key,
            static_key,
        }
    }

    /// Attempt to load router infos.
    fn load_router_infos(path: PathBuf) -> Vec<Vec<u8>> {
        let Ok(router_dir) = std::fs::read_dir(path) else {
            return Vec::new();
        };

        router_dir
            .into_iter()
            .filter_map(|entry| {
                let dir = entry.ok()?.path();

                if !dir.is_dir() {
                    return None;
                }

                Some(
                    std::fs::read_dir(dir)
                        .ok()?
                        .filter_map(|entry| {
                            let file_path = entry.ok()?.path();

                            if !file_path.is_file() {
                                return None;
                            }

                            let mut file = std::fs::File::open(file_path).ok()?;

                            let mut contents = Vec::new();
                            file.read_to_end(&mut contents).ok()?;

                            Some(contents)
                        })
                        .collect::<Vec<_>>(),
                )
            })
            .flatten()
            .collect::<Vec<_>>()
    }

    /// Attempt to load router profiles.
    fn load_router_profiles(path: PathBuf) -> Vec<(String, emissary_core::Profile)> {
        let Ok(profile_dir) = std::fs::read_dir(path) else {
            return Vec::new();
        };

        profile_dir
            .into_iter()
            .filter_map(|entry| {
                let dir = entry.ok()?.path();

                if !dir.is_dir() {
                    return None;
                }

                Some(
                    std::fs::read_dir(dir)
                        .ok()?
                        .filter_map(|entry| {
                            let file_path = entry.ok()?.path();

                            if !file_path.is_file() {
                                return None;
                            }

                            let mut file = std::fs::File::open(&file_path).ok()?;

                            let mut contents = String::new();
                            file.read_to_string(&mut contents).ok()?;

                            let profile = toml::from_str::<Profile>(&contents).ok()?;
                            let name = {
                                let input = file_path.to_str().expect("to succeed");
                                let start = input.find("profile-")?;
                                let start = start + "profile-".len();
                                let end = input.find(".toml")?;

                                input[start..end].to_string()
                            };

                            Some((
                                name,
                                emissary_core::Profile {
                                    last_activity: Duration::from_secs(
                                        profile.last_activity.unwrap_or(0),
                                    ),
                                    last_declined: profile.last_declined.map(Duration::from_secs),
                                    last_dial_failure: profile
                                        .last_dial_failure
                                        .map(Duration::from_secs),
                                    num_accepted: profile.num_accepted.unwrap_or(0),
                                    num_connection: profile.num_connection.unwrap_or(0),
                                    num_dial_failures: profile.num_dial_failures.unwrap_or(0),
                                    num_lookup_failures: profile.num_lookup_failures.unwrap_or(0),
                                    num_lookup_no_responses: profile
                                        .num_lookup_no_responses
                                        .unwrap_or(0),
                                    num_lookup_successes: profile.num_lookup_successes.unwrap_or(0),
                                    num_rejected: profile.num_rejected.unwrap_or(0),
                                    num_selected: profile.num_selected.unwrap_or(0),
                                    num_test_failures: profile.num_test_failures.unwrap_or(0),
                                    num_test_successes: profile.num_test_successes.unwrap_or(0),
                                    num_unaswered: profile.num_unaswered.unwrap_or(0),
                                },
                            ))
                        })
                        .collect::<Vec<_>>(),
                )
            })
            .flatten()
            .collect::<Vec<_>>()
    }

    /// Store local router info into the base path.
    pub async fn store_local_router_info(&self, router_info: Vec<u8>) -> anyhow::Result<()> {
        tokio::fs::write(self.base_path.join("router.info"), &router_info)
            .await
            .map_err(From::from)
    }

    /// Store `router_info` for `router_id` in `netDb`.
    pub fn store_router_info(&self, router_id: String, router_info: Vec<u8>) -> anyhow::Result<()> {
        let dir = router_id.chars().next().ok_or(anyhow!("invalid router id"))?;
        let name = match router_id.ends_with(".dat") {
            true => self.base_path.join(format!("netDb/r{dir}/routerInfo-{router_id}")),
            false => self.base_path.join(format!("netDb/r{dir}/routerInfo-{router_id}.dat")),
        };

        let mut file = File::create(name)?;
        file.write_all(&router_info)?;

        Ok(())
    }

    /// Store `profile` for `router_id` in `peerProfiles`.
    fn store_profile(
        &self,
        router_id: String,
        profile: emissary_core::Profile,
    ) -> anyhow::Result<()> {
        let dir = router_id.chars().next().ok_or(anyhow!("invalid router id"))?;

        // don't store profile on disk if associated router info doesn't exist
        if !Path::exists(&self.base_path.join(format!("netDb/r{dir}/routerInfo-{router_id}.dat"))) {
            tracing::trace!(
                target: LOG_TARGET,
                %router_id,
                "router info doesn't exist, skipping router profile store",
            );

            return Ok(());
        }

        let profile_name =
            self.base_path.join(format!("peerProfiles/p{dir}/profile-{router_id}.toml"));

        let config = toml::to_string(&Profile::from(profile)).expect("to succeed");
        let mut file = File::create(profile_name)?;
        file.write_all(config.as_bytes())?;

        Ok(())
    }

    /// Decompress `bytes`.
    fn decompress(bytes: Vec<u8>) -> Option<Vec<u8>> {
        let mut e = GzDecoder::new(Vec::new());
        e.write_all(bytes.as_ref()).ok()?;

        e.finish().ok()
    }
}

impl emissary_core::runtime::Storage for Storage {
    fn save_to_disk(&self, routers: Vec<(String, Option<Vec<u8>>, emissary_core::Profile)>) {
        let storage_handle = self.clone();

        tokio::task::spawn_blocking(move || {
            for (router_id, router_info, profile) in routers {
                if let Some(router_info) = router_info {
                    match Storage::decompress(router_info) {
                        Some(router_info) =>
                            if let Err(error) =
                                storage_handle.store_router_info(router_id.clone(), router_info)
                            {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    ?router_id,
                                    ?error,
                                    "failed to store router info to disk",
                                );
                            },
                        None => tracing::warn!(
                            target: LOG_TARGET,
                            ?router_id,
                            "failed to decompress router info",
                        ),
                    }
                }

                if let Err(error) = storage_handle.store_profile(router_id.clone(), profile) {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?router_id,
                        ?error,
                        "failed to store router profile to disk",
                    );
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn initialize_storage() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("testdir");

        assert!(tokio::fs::read_dir(&path).await.is_err());
        let storage = Storage::new(Some(path.clone())).await.unwrap();

        // ensure router info directory has been created
        let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~";
        let netdb = path.join("netDb");

        for c in chars.chars() {
            let dir = netdb.join(format!("r{c}"));

            assert!(dir.exists() && dir.is_dir());
        }

        // ensure router profile directory has been created
        let netdb = path.join("peerProfiles");

        for c in chars.chars() {
            let dir = netdb.join(format!("p{c}"));

            assert!(dir.exists() && dir.is_dir());
        }

        assert!(path.join("ssu2.keys").exists());
        assert!(path.join("ntcp2.keys").exists());
        assert!(path.join("static.key").exists());
        assert!(path.join("signing.key").exists());

        // attempt to load router info from disk
        let _ = storage.load().await;
    }

    #[tokio::test]
    async fn initialize_storage_empty_base_directory() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("testdir");
        tokio::fs::create_dir_all(&path).await.unwrap();

        assert!(tokio::fs::read_dir(&path).await.is_ok());
        let storage = Storage::new(Some(path.clone())).await.unwrap();

        // ensure router info directory has been created
        let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~";
        let netdb = path.join("netDb");

        for c in chars.chars() {
            let dir = netdb.join(format!("r{c}"));

            assert!(dir.exists() && dir.is_dir());
        }

        // ensure router profile directory has been created
        let netdb = path.join("peerProfiles");

        for c in chars.chars() {
            let dir = netdb.join(format!("p{c}"));

            assert!(dir.exists() && dir.is_dir());
        }

        assert!(path.join("ssu2.keys").exists());
        assert!(path.join("ntcp2.keys").exists());
        assert!(path.join("static.key").exists());
        assert!(path.join("signing.key").exists());

        // attempt to load router info from disk
        let _ = storage.load().await;
    }

    #[tokio::test]
    async fn remove_netdb() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("testdir");
        tokio::fs::create_dir_all(&path).await.unwrap();

        assert!(tokio::fs::read_dir(&path).await.is_ok());
        let _storage = Storage::new(Some(path.clone())).await.unwrap();

        // ensure router info directory has been created
        let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~";
        let netdb = path.join("netDb");

        for c in chars.chars() {
            let dir = netdb.join(format!("r{c}"));

            assert!(dir.exists() && dir.is_dir());
        }

        // ensure router profile directory has been created
        let netdb = path.join("peerProfiles");

        for c in chars.chars() {
            let dir = netdb.join(format!("p{c}"));

            assert!(dir.exists() && dir.is_dir());
        }

        assert!(path.join("ssu2.keys").exists());
        assert!(path.join("ntcp2.keys").exists());
        assert!(path.join("static.key").exists());
        assert!(path.join("signing.key").exists());

        // remove netdb and verify it doesn't exist
        tokio::fs::remove_dir_all(path.join("netDb")).await.unwrap();
        assert!(!path.join("netDb").exists());

        // reinitialize `Storage` and verify netDb has been created
        let _storage = Storage::new(Some(path.clone())).await.unwrap();

        // ensure router info directory has been created
        let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~";
        let netdb = path.join("netDb");

        for c in chars.chars() {
            let dir = netdb.join(format!("r{c}"));

            assert!(dir.exists() && dir.is_dir());
        }
    }

    #[tokio::test]
    async fn remove_profiles() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("testdir");
        tokio::fs::create_dir_all(&path).await.unwrap();

        assert!(tokio::fs::read_dir(&path).await.is_ok());
        let _storage = Storage::new(Some(path.clone())).await.unwrap();

        // ensure router info directory has been created
        let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~";
        let netdb = path.join("netDb");

        for c in chars.chars() {
            let dir = netdb.join(format!("r{c}"));

            assert!(dir.exists() && dir.is_dir());
        }

        // ensure router profile directory has been created
        let netdb = path.join("peerProfiles");

        for c in chars.chars() {
            let dir = netdb.join(format!("p{c}"));

            assert!(dir.exists() && dir.is_dir());
        }

        assert!(path.join("ssu2.keys").exists());
        assert!(path.join("ntcp2.keys").exists());
        assert!(path.join("static.key").exists());
        assert!(path.join("signing.key").exists());

        // remove peerProfiles and verify it doesn't exist
        tokio::fs::remove_dir_all(path.join("peerProfiles")).await.unwrap();
        assert!(!path.join("peerProfiles").exists());

        // reinitialize `Storage` and verify netDb has been created
        let _storage = Storage::new(Some(path.clone())).await.unwrap();

        // ensure router info directory has been created
        let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~";
        let netdb = path.join("peerProfiles");

        for c in chars.chars() {
            let dir = netdb.join(format!("p{c}"));

            assert!(dir.exists() && dir.is_dir());
        }
    }

    #[tokio::test]
    #[should_panic]
    async fn remove_file_between_init_and_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("testdir");
        tokio::fs::create_dir_all(&path).await.unwrap();

        assert!(tokio::fs::read_dir(&path).await.is_ok());
        let storage = Storage::new(Some(path.clone())).await.unwrap();

        // ensure router info directory has been created
        let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~";
        let netdb = path.join("netDb");

        for c in chars.chars() {
            let dir = netdb.join(format!("r{c}"));

            assert!(dir.exists() && dir.is_dir());
        }

        // ensure router profile directory has been created
        let netdb = path.join("peerProfiles");

        for c in chars.chars() {
            let dir = netdb.join(format!("p{c}"));

            assert!(dir.exists() && dir.is_dir());
        }

        assert!(path.join("ssu2.keys").exists());
        assert!(path.join("ntcp2.keys").exists());
        assert!(path.join("static.key").exists());
        assert!(path.join("signing.key").exists());

        // remove file and attempt to load router info from disk
        tokio::fs::remove_file(path.join("ssu2.keys")).await.unwrap();

        // attempt to load router info from disk
        let _ = storage.load().await;
    }
}

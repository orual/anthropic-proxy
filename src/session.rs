use crate::types::{PkceChallenge, SessionData};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tracing::{debug, error, info};
use uuid::Uuid;

#[derive(Clone, Debug)]
struct CachedSession {
    data: SessionData,
    last_accessed: Instant,
}

#[derive(Debug)]
pub struct SessionStore {
    sessions: RwLock<HashMap<String, SessionData>>,
    pkce_challenges: RwLock<HashMap<String, PkceChallenge>>,
    persist_path: Option<PathBuf>,
    // Simple cache with 5-minute TTL
    session_cache: Arc<RwLock<HashMap<String, CachedSession>>>,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    pub fn new() -> Self {
        let persist_path =
            dirs::data_local_dir().map(|dir| dir.join("anthropic-proxy").join("sessions.json"));

        let store = Self {
            sessions: RwLock::new(HashMap::new()),
            pkce_challenges: RwLock::new(HashMap::new()),
            persist_path: persist_path.clone(),
            session_cache: Arc::new(RwLock::new(HashMap::new())),
        };

        // Load existing sessions if file exists
        if let Some(path) = &persist_path {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            store.load_sessions();
        }

        store
    }

    fn load_sessions(&self) {
        if let Some(path) = &self.persist_path {
            match fs::read_to_string(path) {
                Ok(data) => {
                    if let Ok(sessions) =
                        serde_json::from_str::<HashMap<String, SessionData>>(&data)
                    {
                        let mut store = self.sessions.write().unwrap();
                        *store = sessions;
                        info!("Loaded {} sessions from disk", store.len());
                    } else {
                        debug!("Failed to parse sessions file");
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    debug!("No existing sessions file found");
                }
                Err(e) => {
                    error!("Failed to load sessions: {}", e);
                }
            }
        }
    }

    fn save_sessions(&self) {
        if let Some(path) = &self.persist_path {
            let sessions = self.sessions.read().unwrap();
            match serde_json::to_string_pretty(&*sessions) {
                Ok(data) => {
                    if let Err(e) = fs::write(path, data) {
                        error!("Failed to save sessions: {}", e);
                    } else {
                        debug!("Saved {} sessions to disk", sessions.len());
                    }
                }
                Err(e) => {
                    error!("Failed to serialize sessions: {}", e);
                }
            }
        }
    }

    pub fn create_session(&self, session_id: &str, data: SessionData) {
        // Save to persistent store
        let mut sessions = self.sessions.write().unwrap();
        sessions.insert(session_id.to_string(), data.clone());
        drop(sessions); // Release lock before saving
        self.save_sessions();

        // Add to cache
        let mut cache = self.session_cache.write().unwrap();
        cache.insert(
            session_id.to_string(),
            CachedSession {
                data,
                last_accessed: Instant::now(),
            },
        );
    }

    pub fn get_session(&self, session_id: &str) -> Option<SessionData> {
        // Check cache first
        {
            let mut cache = self.session_cache.write().unwrap();

            // Clean up expired entries
            cache.retain(|_, cached| cached.last_accessed.elapsed() < Duration::from_secs(300));

            if let Some(cached) = cache.get_mut(session_id) {
                cached.last_accessed = Instant::now();
                debug!("Session cache hit for: {}", session_id);
                return Some(cached.data.clone());
            }
        }

        // Not in cache, check persistent store
        let sessions = self.sessions.read().unwrap();
        if let Some(session) = sessions.get(session_id).cloned() {
            // Add to cache
            let mut cache = self.session_cache.write().unwrap();
            cache.insert(
                session_id.to_string(),
                CachedSession {
                    data: session.clone(),
                    last_accessed: Instant::now(),
                },
            );
            debug!("Session loaded from disk and cached: {}", session_id);
            Some(session)
        } else {
            None
        }
    }

    pub fn update_session(&self, session_id: &str, data: SessionData) {
        // Update in persistent store
        let mut sessions = self.sessions.write().unwrap();
        sessions.insert(session_id.to_string(), data.clone());
        drop(sessions); // Release lock before saving
        self.save_sessions();

        // Update cache
        let mut cache = self.session_cache.write().unwrap();
        cache.insert(
            session_id.to_string(),
            CachedSession {
                data,
                last_accessed: Instant::now(),
            },
        );
    }

    pub fn delete_session(&self, session_id: &str) {
        // Remove from persistent store
        let mut sessions = self.sessions.write().unwrap();
        sessions.remove(session_id);
        drop(sessions); // Release lock before saving
        self.save_sessions();

        // Remove from cache
        let mut cache = self.session_cache.write().unwrap();
        cache.remove(session_id);
    }

    pub fn store_pkce_challenge(&self, state: &str, challenge: PkceChallenge) {
        let mut challenges = self.pkce_challenges.write().unwrap();
        challenges.insert(state.to_string(), challenge);
    }

    pub fn get_pkce_challenge(&self, state: &str) -> Option<PkceChallenge> {
        let challenges = self.pkce_challenges.read().unwrap();
        challenges.get(state).cloned()
    }

    pub fn remove_pkce_challenge(&self, state: &str) {
        let mut challenges = self.pkce_challenges.write().unwrap();
        challenges.remove(state);
    }

    pub fn generate_session_id() -> String {
        Uuid::new_v4().to_string()
    }
}

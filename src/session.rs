use crate::types::{PkceChallenge, SessionData};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

#[derive(Debug)]
pub struct SessionStore {
    sessions: RwLock<HashMap<String, SessionData>>,
    pkce_challenges: RwLock<HashMap<String, PkceChallenge>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            pkce_challenges: RwLock::new(HashMap::new()),
        }
    }

    pub fn create_session(&self, session_id: &str, data: SessionData) {
        let mut sessions = self.sessions.write().unwrap();
        sessions.insert(session_id.to_string(), data);
    }

    pub fn get_session(&self, session_id: &str) -> Option<SessionData> {
        let sessions = self.sessions.read().unwrap();
        sessions.get(session_id).cloned()
    }

    pub fn update_session(&self, session_id: &str, data: SessionData) {
        let mut sessions = self.sessions.write().unwrap();
        sessions.insert(session_id.to_string(), data);
    }

    pub fn delete_session(&self, session_id: &str) {
        let mut sessions = self.sessions.write().unwrap();
        sessions.remove(session_id);
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

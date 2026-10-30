//! Where a scan is while it runs: the phase, how many ports are done and the
//! highest one reached, the open ports found so far, which services are being
//! inspected, what each port that is done turned out to expose, and the DNS
//! records once they're in. The checks run while the sweep goes on, so all of
//! these fill in at once.
//! `--serve` hands a snapshot to the dashboard, which draws the scan as it
//! goes.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use serde::Serialize;
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    #[default]
    Queued,
    Resolving,
    Ports,
    Endpoints,
    Done,
}

#[derive(Default)]
pub struct Progress {
    phase: Mutex<Phase>,
    ip: Mutex<String>,
    ports_total: AtomicUsize,
    ports_done: AtomicUsize,
    /// The highest port whose probe has finished.
    port: AtomicUsize,
    open: Mutex<Vec<u16>>,
    services_total: AtomicUsize,
    services_done: AtomicUsize,
    /// The ports whose HTTP services are being inspected.
    inspecting: Mutex<BTreeSet<u16>>,
    /// Each port that is done, with its endpoints and findings.
    found: Mutex<HashMap<u16, Value>>,
    /// What each service that spoke first said.
    banners: Mutex<HashMap<u16, String>>,
    /// The DNS records and their findings, once the lookup is done.
    dns: Mutex<Value>,
}

impl Progress {
    pub fn set_phase(&self, phase: Phase) {
        *self.phase.lock().unwrap_or_else(|e| e.into_inner()) = phase;
    }

    pub fn start_ports(&self, ip: &str, total: usize) {
        *self.ip.lock().unwrap_or_else(|e| e.into_inner()) = ip.to_string();
        self.ports_total.store(total, Ordering::Relaxed);
        self.set_phase(Phase::Ports);
    }

    pub fn port_done(&self, port: u16, open: bool) {
        self.ports_done.fetch_add(1, Ordering::Relaxed);
        self.port.fetch_max(port as usize, Ordering::Relaxed);
        if open {
            self.open.lock().unwrap_or_else(|e| e.into_inner()).push(port);
        }
    }

    /// One more HTTP service is waiting to be inspected.
    pub fn service_found(&self) {
        self.services_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inspecting(&self, port: u16) {
        self.inspecting.lock().unwrap_or_else(|e| e.into_inner()).insert(port);
    }

    pub fn inspected(&self, port: u16) {
        self.services_done.fetch_add(1, Ordering::Relaxed);
        self.inspecting.lock().unwrap_or_else(|e| e.into_inner()).remove(&port);
    }

    pub fn dns(&self, found: Value) {
        *self.dns.lock().unwrap_or_else(|e| e.into_inner()) = found;
    }

    pub fn banner(&self, port: u16, text: &str) {
        let mut banners = self.banners.lock().unwrap_or_else(|e| e.into_inner());
        banners.insert(port, text.to_string());
    }

    /// What one open port exposes, once nothing more is coming for it.
    pub fn checked(&self, port: u16, what: Value) {
        let mut found = self.found.lock().unwrap_or_else(|e| e.into_inner());
        found.insert(port, what);
    }

    pub fn snapshot(&self) -> Value {
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner()).clone();
        open.sort_unstable();
        let found = self.found.lock().unwrap_or_else(|e| e.into_inner());
        let banners = self.banners.lock().unwrap_or_else(|e| e.into_inner());
        let open: Vec<Value> = open
            .iter()
            .map(|p| {
                let service = scanner::ports::service_name(*p);
                json!({ "port": p, "service": service, "banner": banners.get(p), "found": found.get(p) })
            })
            .collect();
        let inspecting: Vec<u16> = self
            .inspecting
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .copied()
            .collect();
        json!({
            "phase": *self.phase.lock().unwrap_or_else(|e| e.into_inner()),
            "ip": *self.ip.lock().unwrap_or_else(|e| e.into_inner()),
            "ports_total": self.ports_total.load(Ordering::Relaxed),
            "ports_done": self.ports_done.load(Ordering::Relaxed),
            "port": self.port.load(Ordering::Relaxed),
            "open": open,
            "services_total": self.services_total.load(Ordering::Relaxed),
            "services_done": self.services_done.load(Ordering::Relaxed),
            "inspecting": inspecting,
            "dns": *self.dns.lock().unwrap_or_else(|e| e.into_inner()),
        })
    }
}

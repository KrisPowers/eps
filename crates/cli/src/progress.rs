//! Where a scan is while it runs: the phase, how many ports are done and the
//! highest one reached, the open ports found so far, and which service is
//! being inspected. `--serve` hands a snapshot to the dashboard, which draws
//! the scan as it goes.

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
    /// The port whose HTTP service is being inspected, 0 for none.
    inspecting: AtomicUsize,
    endpoints: AtomicUsize,
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

    pub fn start_endpoints(&self, services: usize) {
        self.services_total.store(services, Ordering::Relaxed);
        self.set_phase(Phase::Endpoints);
    }

    pub fn inspecting(&self, port: u16) {
        self.inspecting.store(port as usize, Ordering::Relaxed);
    }

    pub fn inspected(&self, endpoints: usize) {
        self.services_done.fetch_add(1, Ordering::Relaxed);
        self.endpoints.fetch_add(endpoints, Ordering::Relaxed);
        self.inspecting.store(0, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> Value {
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner()).clone();
        open.sort_unstable();
        let open: Vec<Value> = open
            .iter()
            .map(|p| json!({ "port": p, "service": scanner::ports::service_name(*p) }))
            .collect();
        let inspecting = self.inspecting.load(Ordering::Relaxed);
        json!({
            "phase": *self.phase.lock().unwrap_or_else(|e| e.into_inner()),
            "ip": *self.ip.lock().unwrap_or_else(|e| e.into_inner()),
            "ports_total": self.ports_total.load(Ordering::Relaxed),
            "ports_done": self.ports_done.load(Ordering::Relaxed),
            "port": self.port.load(Ordering::Relaxed),
            "open": open,
            "services_total": self.services_total.load(Ordering::Relaxed),
            "services_done": self.services_done.load(Ordering::Relaxed),
            "inspecting": if inspecting == 0 { Value::Null } else { json!(inspecting) },
            "endpoints": self.endpoints.load(Ordering::Relaxed),
        })
    }
}

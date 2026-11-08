use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Puerto que abstrae el reloj del sistema para permitir determinismo en tests.
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

/// Implementación real del reloj basada en `Instant::now()`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl SystemClock {
    pub fn new() -> Self {
        Self
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Implementación simulada del reloj para pruebas sin esperas reales (`sleep`).
#[derive(Debug)]
pub struct FakeClock {
    now: Mutex<Instant>,
}

impl FakeClock {
    pub fn new() -> Self {
        Self {
            now: Mutex::new(Instant::now()),
        }
    }

    pub fn with_instant(instant: Instant) -> Self {
        Self {
            now: Mutex::new(instant),
        }
    }

    pub fn advance(&self, duration: Duration) {
        let mut lock = self.now.lock().expect("FakeClock mutex poisoned");
        *lock += duration;
    }
}

impl Default for FakeClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Instant {
        *self.now.lock().expect("FakeClock mutex poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_clock_advances() {
        let clock = SystemClock::new();
        let t1 = clock.now();
        std::thread::sleep(Duration::from_millis(5));
        let t2 = clock.now();
        assert!(t2 >= t1);
    }

    #[test]
    fn test_fake_clock_advance() {
        let clock = FakeClock::new();
        let t1 = clock.now();

        clock.advance(Duration::from_secs(60));
        let t2 = clock.now();
        assert_eq!(t2.duration_since(t1), Duration::from_secs(60));

        clock.advance(Duration::from_millis(500));
        let t3 = clock.now();
        assert_eq!(t3.duration_since(t2), Duration::from_millis(500));
    }

    #[test]
    fn test_fake_clock_default() {
        let clock = FakeClock::default();
        let t1 = clock.now();
        clock.advance(Duration::from_secs(10));
        let t2 = clock.now();
        assert_eq!(t2.duration_since(t1), Duration::from_secs(10));
    }
}

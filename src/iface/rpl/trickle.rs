use crate::{rand::Rand, time::Duration, time::Instant, Result};

#[derive(Debug)]
pub struct TrickleTimer {
    i_min: u32,
    i_max: u32,
    k: usize,

    i: Duration,
    t: Duration,
    t_expiration: Instant,
    i_expiration: Instant,
    counter: usize,
}

fn map(x: f32, in_min: f32, in_max: f32, out_min: f32, out_max: f32) -> f32 {
    (x - in_min) * (out_max - out_min) / (in_max - in_min) + out_min
}

impl TrickleTimer {
    /// Create a new Trickle timer.
    pub fn new(now: Instant, i_min: u32, i_max: u32, k: usize, rand: &mut Rand) -> Self {
        // NOTE: the standard defines I as a random number between [Imin,Imax]. However, this could
        // result in a t value that is very close to Imax. Therefore, sending DIO messages will be
        // sporadic, which is not ideal when a network is started. Hence, we do not draw a random
        // number, but just use Imin for I. This only affects the start of the RPL tree and speeds
        // this up a little.
        //
        // It should have been:
        // ```
        // let i = Duration::from_millis(
        //     (2u32.pow(i_min) + rand.rand_u32() % (2u32.pow(i_max) - 2u32.pow(i_min) + 1)) as u64,
        // );
        // ```
        let i = Duration::from_millis(2u32.pow(i_min) as u64);

        let t = Duration::from_micros(
            i.total_micros() / 2
                + (rand.rand_u32() as u64 % (i.total_micros() - i.total_micros() / 2 + 1)),
        );

        Self {
            i_min,
            i_max,
            k,
            i,
            t,
            t_expiration: now + t,
            i_expiration: now + i,
            counter: 0,
        }
    }

    #[inline]
    pub fn poll(&mut self, now: Instant, rand: &mut Rand) -> bool {
        let can_transmit = self.can_transmit() && self.t_expired(now);

        if can_transmit {
            self.set_t(now, rand);
        }

        if self.i_expired(now) {
            self.expire(now, rand);
        }

        can_transmit
    }

    #[inline]
    pub fn poll_at(&self) -> Instant {
        self.t_expiration.min(self.i_expiration)
    }

    #[inline]
    pub fn set_t(&mut self, now: Instant, rand: &mut Rand) {
        let t = Duration::from_micros(
            self.i.total_micros() / 2
                + (rand.rand_u32() as u64
                    % (self.i.total_micros() - self.i.total_micros() / 2 + 1)),
        );

        self.t = t;
        self.t_expiration = now + t;
    }

    /// Check if the timer expired.
    #[inline]
    pub(crate) fn t_expired(&self, now: Instant) -> bool {
        now >= self.t_expiration
    }

    pub fn t_expires_at(&self) -> Instant {
        self.t_expiration
    }

    pub(crate) fn i_expired(&self, now: Instant) -> bool {
        now >= self.i_expiration
    }

    /// Signal the Trickle timer that a consistency has been heard.
    #[inline]
    pub fn hear_consistent(&mut self) {
        self.counter += 1;
    }

    /// Signal the Trickle timer that an inconsistency has been heard.
    pub fn hear_inconsistent(&mut self, now: Instant, rand: &mut Rand) {
        let min_interval = Duration::from_millis(2u32.pow(self.i_min) as u64);
        if self.i > min_interval {
            self.i = min_interval;
            self.i_expiration = now + self.i;

            self.counter = 0;
            self.set_t(now, rand);
        }
    }

    /// Check if the trickle timer can transmit.
    pub fn can_transmit(&self) -> bool {
        self.k != 0 && self.counter < self.k
    }

    /// Resets the Trickle timer, according to the standard, when it has expired.
    pub fn expire(&mut self, now: Instant, rand: &mut Rand) {
        // Double the interval I
        self.i = self.i + self.i;

        let max_interval = Duration::from_millis(2u32.pow(self.i_max) as u64);
        if self.i > max_interval {
            self.i = max_interval;
        }

        self.i_expiration = now + self.i;
        self.counter = 0;
        self.set_t(now, rand);
    }

    pub fn start(&mut self, now: Instant, rand: &mut Rand) {
        todo!();
    }

    /// Reset the trickle timer.
    #[inline]
    pub fn reset(&mut self, now: Instant, rand: &mut Rand) {
        let i = Duration::from_millis(2u32.pow(self.i_min) as u64);
        self.i = i;
        self.i_expiration = now + i;

        self.set_t(now, rand);
    }

    pub fn max_expiration(&self) -> Duration {
        Duration::from_millis(2u32.pow(self.i_max) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}

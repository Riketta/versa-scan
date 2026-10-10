//! `BatchPlanner` - the pure state machine behind scan batching.
//!
//! This is the C# worker's `ProduceAvScanTaskLoop` decision tree, extracted:
//! - Same-priority requests fill the open batch up to capacity.
//! - A higher-priority request parks the open batch and opens a new one
//!   (preemption); parked batches resurface when the planner is empty again.
//! - A lower-priority request closes the open batch (it gets scanned now
//!   rather than mixing priorities) and opens a new one.
//! - A full batch is emitted as ready.
//! - `flush` closes the open batch when the consumer goes idle - unlike the
//!   C# loop, which closed a task the instant the queue drained (often
//!   producing 1-file scans), the orchestrator gives it a grace period.
//!
//! Emits [`PlannerEvent`]s; the orchestrator turns each ready batch into a
//! scan run. Pure and synchronous - all I/O lives elsewhere.

use std::collections::BinaryHeap;

use crate::models::batch::ScanBatch;
use crate::models::ids::{BatchId, SampleId};
use crate::models::priority::Priority;
use crate::models::sample::SampleRequest;

/// What `feed`/`flush` produced.
#[derive(Debug, Default)]
pub struct PlannerEvent {
    /// Batches ready to scan right now (closed full / closed by priority
    /// switch / flushed / displaced).
    pub ready: Vec<ScanBatch>,
    /// Sample ids the planner refused (duplicate within the open batch
    /// window, i.e. a broker re-delivery racing its twin). The orchestrator
    /// settles their deliveries by id.
    pub rejected: Vec<SampleId>,
}

/// Max-heap entry: higher priority first, older batch first on ties.
#[derive(Debug)]
struct Parked {
    batch: ScanBatch,
    seq: u64,
}

impl PartialEq for Parked {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

impl Eq for Parked {}

impl PartialOrd for Parked {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Parked {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.batch.priority().cmp(&self.batch.priority()).then(self.seq.cmp(&other.seq))
    }
}

#[derive(Debug)]
pub struct BatchPlanner {
    capacity: usize,
    open: Option<ScanBatch>,
    parked: BinaryHeap<Parked>,
    next_seq: u64,
}

impl BatchPlanner {
    pub fn new(capacity: usize) -> Self {
        Self { capacity, open: None, parked: BinaryHeap::new(), next_seq: 0 }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The open batch's priority, if one is open.
    pub fn open_priority(&self) -> Option<Priority> {
        self.open.as_ref().map(ScanBatch::priority)
    }

    /// True when nothing is open or parked - the planner forgot everything
    /// that ever arrived.
    pub fn is_idle(&self) -> bool {
        self.open.is_none() && self.parked.is_empty()
    }

    /// True when a batch currently held by the planner (open or parked)
    /// already contains this sample. The orchestrator uses it as a
    /// duplicate-delivery guard so a broker re-delivery cannot join a batch
    /// its twin is still sitting in.
    pub fn contains(&self, sample_id: &SampleId) -> bool {
        let in_open = self
            .open
            .as_ref()
            .is_some_and(|b| b.files().iter().any(|f| &f.request.sample_id == sample_id));
        in_open
            || self
                .parked
                .iter()
                .any(|p| p.batch.files().iter().any(|f| &f.request.sample_id == sample_id))
    }

    fn fresh_batch(&mut self, priority: Priority) -> ScanBatch {
        let id = BatchId::new(uuid::Uuid::new_v4().to_string())
            .unwrap_or_else(|_| BatchId::new("batch").expect("static id is valid"));
        ScanBatch::new(id, priority, self.capacity)
    }

    /// Feeds one request into the planner.
    pub fn feed(&mut self, request: SampleRequest) -> PlannerEvent {
        let mut event = PlannerEvent::default();

        match self.open.take() {
            None => {
                // Restore a parked batch only if it matches the incoming
                // priority exactly. A parked batch with a *higher* priority
                // stays parked (adding a lower-priority request to it would
                // violate the batch invariant); a lower-priority parked batch
                // must not jump the incoming request.
                let restored = match self.parked.peek() {
                    Some(top) if top.batch.priority() == request.priority => {
                        self.parked.pop().map(|p| p.batch)
                    }
                    _ => None,
                };
                let mut batch = restored.unwrap_or_else(|| self.fresh_batch(request.priority));
                self.try_add(&mut batch, request, &mut event);
                self.seal_if_full(batch, &mut event);
            }
            Some(open) => {
                if open.priority() < request.priority {
                    // Preempt: park the open batch, serve the important one now.
                    self.next_seq += 1;
                    self.parked.push(Parked { batch: open, seq: self.next_seq });
                    let mut batch = self.fresh_batch(request.priority);
                    self.try_add(&mut batch, request, &mut event);
                    self.open = Some(batch);
                } else if open.priority() > request.priority {
                    // Close the open batch so the lower-priority request gets
                    // its own batch instead of waiting behind a scan.
                    event.ready.push(open);
                    let mut batch = self.fresh_batch(request.priority);
                    self.try_add(&mut batch, request, &mut event);
                    self.seal_if_full(batch, &mut event);
                } else {
                    let mut batch = open;
                    if self.try_add(&mut batch, request, &mut event) && batch.is_full() {
                        event.ready.push(batch);
                    } else {
                        self.open = Some(batch);
                    }
                }
            }
        }

        event
    }

    /// Closes the open batch (consumer idle / shutdown). Parked batches stay
    /// parked - they resurface when new requests arrive.
    pub fn flush(&mut self) -> PlannerEvent {
        let mut event = PlannerEvent::default();
        if let Some(open) = self.open.take() {
            if !open.is_empty() {
                event.ready.push(open);
            }
        }
        event
    }

    /// Returns true when the request was added.
    fn try_add(
        &self,
        batch: &mut ScanBatch,
        request: SampleRequest,
        event: &mut PlannerEvent,
    ) -> bool {
        match batch.try_add(request) {
            Ok(()) => true,
            Err(err) => {
                tracing::warn!(error = %err, "planner rejected request");
                if let crate::models::batch::BatchAddError::DuplicateSample(id) = err {
                    event.rejected.push(id);
                }
                false
            }
        }
    }

    fn seal_if_full(&mut self, batch: ScanBatch, event: &mut PlannerEvent) {
        if batch.is_full() {
            event.ready.push(batch);
        } else {
            self.open = Some(batch);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use crate::models::digest::Sha256Digest;
    use crate::models::ids::CorrelationId;
    use crate::models::sample::ReportDest;
    use time::OffsetDateTime;

    const CAP: usize = 3;

    fn request(id: &str, priority: Priority) -> SampleRequest {
        SampleRequest {
            sample_id: SampleId::new(id).unwrap(),
            url: format!("http://art/samples/{id}"),
            sha256: Sha256Digest::from_hex(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            )
            .unwrap(),
            size: 1,
            priority,
            report_dest: ReportDest::new("reports"),
            correlation_id: CorrelationId::new("corr").unwrap(),
            extensions: vec![],
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn planner() -> BatchPlanner {
        BatchPlanner::new(CAP)
    }

    fn ids(batch: &ScanBatch) -> Vec<String> {
        batch.files().iter().map(|f| f.request.sample_id.as_str().to_owned()).collect()
    }

    #[test]
    fn fills_batch_and_closes_when_full() {
        let mut p = planner();
        let e1 = p.feed(request("a", Priority::Normal));
        assert!(e1.ready.is_empty() && e1.rejected.is_empty());
        assert_eq!(p.open_priority(), Some(Priority::Normal));

        let e2 = p.feed(request("b", Priority::Normal));
        assert!(e2.ready.is_empty());
        let e3 = p.feed(request("c", Priority::Normal));
        assert_eq!(e3.ready.len(), 1);
        assert_eq!(ids(&e3.ready[0]), vec!["a", "b", "c"]);
        assert_eq!(p.open_priority(), None);
    }

    #[test]
    fn higher_priority_parks_open_batch() {
        let mut p = planner();
        p.feed(request("l1", Priority::Low));
        p.feed(request("l2", Priority::Low));

        let e = p.feed(request("h1", Priority::High));
        assert!(e.ready.is_empty(), "parked batch is not ready");
        assert_eq!(p.open_priority(), Some(Priority::High));

        // The parked batch resurfaces after the high batch completes. The
        // next low request restores it; adding l3 fills it to capacity, so
        // the restored batch closes immediately.
        let f = p.flush();
        assert_eq!(f.ready.len(), 1);
        assert_eq!(ids(&f.ready[0]), vec!["h1"]);

        let g = p.feed(request("l3", Priority::Low));
        assert_eq!(g.ready.len(), 1, "restored batch refilled to capacity");
        assert_eq!(ids(&g.ready[0]), vec!["l1", "l2", "l3"]);
        assert_eq!(p.open_priority(), None);
    }

    #[test]
    fn lower_priority_closes_open_batch() {
        let mut p = planner();
        p.feed(request("h1", Priority::High));

        let e = p.feed(request("l1", Priority::Low));
        assert_eq!(e.ready.len(), 1);
        assert_eq!(ids(&e.ready[0]), vec!["h1"]);
        assert_eq!(p.open_priority(), Some(Priority::Low));
    }

    #[test]
    fn flush_emits_open_batch() {
        let mut p = planner();
        p.feed(request("a", Priority::Normal));
        p.feed(request("b", Priority::Normal));
        let e = p.flush();
        assert_eq!(e.ready.len(), 1);
        assert_eq!(ids(&e.ready[0]), vec!["a", "b"]);
        assert!(p.open_priority().is_none());
        // Second flush is a no-op.
        assert!(p.flush().ready.is_empty());
    }

    #[test]
    fn parked_batches_resurface_in_priority_order() {
        let mut p = planner();
        // A lower-priority request CLOSES the open high batch (no mixing).
        p.feed(request("h1", Priority::High));
        let close_high = p.feed(request("n1", Priority::Normal));
        assert_eq!(close_high.ready.len(), 1);
        assert_eq!(ids(&close_high.ready[0]), vec!["h1"]);

        // Same again: normal open batch closed by a low request.
        let close_normal = p.feed(request("l1", Priority::Low));
        assert_eq!(close_normal.ready.len(), 1);
        assert_eq!(ids(&close_normal.ready[0]), vec!["n1"]);
        assert_eq!(p.open_priority(), Some(Priority::Low));

        // A high request parks the open low batch.
        let park_low = p.feed(request("h2", Priority::High));
        assert!(park_low.ready.is_empty());
        assert_eq!(p.open_priority(), Some(Priority::High));

        // Draining: flush high; the next high request must restore the parked
        // LOW batch only when priorities match - a high request opens fresh.
        let f = p.flush();
        assert_eq!(ids(&f.ready[0]), vec!["h2"]);
        let g = p.feed(request("h3", Priority::High));
        assert_eq!(ids(p.open.as_ref().unwrap()), vec!["h3"]);
        assert!(g.ready.is_empty());
        let f2 = p.flush();
        assert_eq!(ids(&f2.ready[0]), vec!["h3"]);

        // A normal request does not touch the parked low batch.
        let g2 = p.feed(request("n2", Priority::Normal));
        assert_eq!(ids(p.open.as_ref().unwrap()), vec!["n2"]);
        assert!(g2.ready.is_empty());
        let f3 = p.flush();
        assert_eq!(ids(&f3.ready[0]), vec!["n2"]);

        // Only now does the parked low batch resurface.
        let g3 = p.feed(request("l2", Priority::Low));
        assert_eq!(ids(p.open.as_ref().unwrap()), vec!["l1", "l2"]);
        assert!(g3.ready.is_empty());
        assert_eq!(p.flush().ready.len(), 1);
        assert!(p.is_idle());
    }

    #[test]
    fn duplicate_sample_is_rejected() {
        let mut p = planner();
        p.feed(request("dup", Priority::Normal));
        let e = p.feed(request("dup", Priority::Normal));
        assert_eq!(e.rejected.len(), 1);
        assert_eq!(e.rejected[0].as_str(), "dup");
        assert_eq!(p.open.as_ref().map(|b| b.len()), Some(1));
    }

    #[test]
    fn higher_parked_batch_not_polluted_by_lower_request() {
        let mut p = planner();
        p.feed(request("h1", Priority::High));
        // Lower priority closes h1 instead of parking it.
        let park = p.feed(request("l1", Priority::Low));
        assert_eq!(park.ready.len(), 1);
        assert_eq!(ids(&park.ready[0]), vec!["h1"]);
        // Park a fresh low batch with a high request.
        p.feed(request("l2", Priority::Low));
        let park2 = p.feed(request("h2", Priority::High));
        assert!(park2.ready.is_empty());
        // A normal request must NOT be added to the parked low batch; it
        // also CLOSES the open high batch (h2) - no priority mixing.
        let g = p.feed(request("n1", Priority::Normal));
        assert_eq!(g.ready.len(), 1, "open high batch closed by lower priority");
        assert_eq!(ids(&g.ready[0]), vec!["h2"]);
        assert_eq!(p.open_priority(), Some(Priority::Normal));
        assert_eq!(ids(p.open.as_ref().unwrap()), vec!["n1"]);
        let f = p.flush();
        assert_eq!(f.ready.len(), 1);
        // And a high request opens fresh too - the parked low batch stays
        // parked until a matching-priority request arrives.
        let h = p.feed(request("h3", Priority::High));
        assert_eq!(ids(p.open.as_ref().unwrap()), vec!["h3"]);
        assert!(h.ready.is_empty());
        assert_eq!(p.flush().ready.len(), 1);
        // Parked low batch finally resurfaces; l3 fills it to capacity.
        let last = p.feed(request("l3", Priority::Low));
        assert_eq!(last.ready.len(), 1, "restored batch refilled to capacity");
        assert_eq!(ids(&last.ready[0]), vec!["l1", "l2", "l3"]);
        assert!(p.open_priority().is_none());
        assert!(p.is_idle());
    }
}

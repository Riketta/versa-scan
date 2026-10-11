//! `ScanBatch` - the aggregate. One scanner run over a group of samples.
//!
//! Invariants: a batch holds at most `capacity` files, all at the same
//! priority, with unique sample ids. Pure: no I/O, fully unit-testable.

use super::ids::{BatchId, SampleId};
use super::priority::Priority;
use super::sample::SampleRequest;

/// A request placed into a batch, bound to its on-disk name inside the batch
/// workspace (the sample id - unique per batch by invariant).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchFile {
    pub request: SampleRequest,
    pub local_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BatchAddError {
    #[error("batch is full (capacity {capacity})")]
    Full { capacity: usize },
    #[error("priority mismatch: batch {batch}, request {request}")]
    PriorityMismatch { batch: Priority, request: Priority },
    #[error("duplicate sample id {0} in batch")]
    DuplicateSample(SampleId),
}

#[derive(Debug, Clone)]
pub struct ScanBatch {
    id: BatchId,
    priority: Priority,
    capacity: usize,
    files: Vec<BatchFile>,
}

impl ScanBatch {
    pub fn new(id: BatchId, priority: Priority, capacity: usize) -> Self {
        Self { id, priority, capacity, files: Vec::new() }
    }

    pub fn id(&self) -> &BatchId {
        &self.id
    }

    pub fn priority(&self) -> Priority {
        self.priority
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.files.len() >= self.capacity
    }

    pub fn files(&self) -> &[BatchFile] {
        &self.files
    }

    /// Takes all files out of the batch (leaves it empty).
    pub fn drain(&mut self) -> Vec<BatchFile> {
        std::mem::take(&mut self.files)
    }

    /// Adds a request. Fails if the batch is full, the priority differs, or
    /// the sample id is already present.
    pub fn try_add(&mut self, request: SampleRequest) -> Result<(), BatchAddError> {
        if self.is_full() {
            return Err(BatchAddError::Full { capacity: self.capacity });
        }
        if request.priority != self.priority {
            return Err(BatchAddError::PriorityMismatch {
                batch: self.priority,
                request: request.priority,
            });
        }
        if self.files.iter().any(|f| f.request.sample_id == request.sample_id) {
            return Err(BatchAddError::DuplicateSample(request.sample_id));
        }
        let local_name = request.sample_id.as_str().to_owned();
        self.files.push(BatchFile { request, local_name });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::super::digest::Sha256Digest;
    use super::*;
    use crate::models::ids::CorrelationId;
    use crate::models::sample::ReportDest;

    fn request(id: &str, priority: Priority) -> SampleRequest {
        SampleRequest {
            sample_id: SampleId::new(id).unwrap(),
            url: "http://art/samples/x".to_owned(),
            sha256: Sha256Digest::from_hex(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            )
            .unwrap(),
            size: 10,
            priority,
            report_dest: ReportDest::new("reports").unwrap(),
            correlation_id: CorrelationId::new("corr").unwrap(),
            extensions: vec![],
            created_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn fills_to_capacity_then_rejects() {
        let mut batch = ScanBatch::new(BatchId::new("b1").unwrap(), Priority::Normal, 2);
        assert!(batch.try_add(request("a", Priority::Normal)).is_ok());
        assert!(batch.try_add(request("b", Priority::Normal)).is_ok());
        assert!(batch.is_full());
        assert_eq!(
            batch.try_add(request("c", Priority::Normal)),
            Err(BatchAddError::Full { capacity: 2 })
        );
    }

    #[test]
    fn rejects_foreign_priority() {
        let mut batch = ScanBatch::new(BatchId::new("b1").unwrap(), Priority::High, 2);
        assert_eq!(
            batch.try_add(request("a", Priority::Low)),
            Err(BatchAddError::PriorityMismatch { batch: Priority::High, request: Priority::Low })
        );
    }

    #[test]
    fn rejects_duplicate_sample() {
        let mut batch = ScanBatch::new(BatchId::new("b1").unwrap(), Priority::Normal, 4);
        assert!(batch.try_add(request("dup", Priority::Normal)).is_ok());
        assert!(matches!(
            batch.try_add(request("dup", Priority::Normal)),
            Err(BatchAddError::DuplicateSample(_))
        ));
    }

    #[test]
    fn drain_empties() {
        let mut batch = ScanBatch::new(BatchId::new("b1").unwrap(), Priority::Normal, 2);
        assert!(batch.try_add(request("a", Priority::Normal)).is_ok());
        let files = batch.drain();
        assert_eq!(files.len(), 1);
        assert!(batch.is_empty());
    }
}

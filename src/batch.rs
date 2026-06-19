//! Batch and pipelined statement execution (port of Go batch.go).

use std::future::Future;
use std::sync::Arc;

use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;

use crate::error::{Error, Result};
use crate::schema::Statement;

/// Default chunk size for [`ConnectionPool::pipeline_exec`](crate::ConnectionPool::pipeline_exec).
pub const DEFAULT_CHUNK_SIZE: usize = 100;
/// Default worker count for pipelined execution.
pub const DEFAULT_MAX_WORKERS: usize = 8;

/// Split statements into contiguous chunks of at most `chunk_size`.
/// A `chunk_size` of 0 is treated as [`DEFAULT_CHUNK_SIZE`].
pub(crate) fn chunk_statements(stmts: &[Statement], chunk_size: usize) -> Vec<Vec<Statement>> {
    let chunk_size = if chunk_size == 0 {
        DEFAULT_CHUNK_SIZE
    } else {
        chunk_size
    };
    stmts.chunks(chunk_size).map(|c| c.to_vec()).collect()
}

/// Run `exec` over the chunks of `stmts` with bounded concurrency.
/// First error stops dispatching new chunks; in-flight chunks complete.
/// Returns the first error recorded (or Ok if all succeed).
pub(crate) async fn pipeline_drive<F, Fut>(
    stmts: &[Statement],
    chunk_size: usize,
    max_workers: usize,
    exec: F,
) -> Result<()>
where
    F: Fn(Vec<Statement>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    if stmts.is_empty() {
        return Ok(());
    }
    let max_workers = if max_workers == 0 {
        DEFAULT_MAX_WORKERS
    } else {
        max_workers
    };
    let chunks = chunk_statements(stmts, chunk_size);

    let sem = Arc::new(Semaphore::new(max_workers));
    let first_err: Arc<Mutex<Option<Error>>> = Arc::new(Mutex::new(None));
    let exec = Arc::new(exec);
    let mut set: JoinSet<()> = JoinSet::new();

    for chunk in chunks {
        // Stop dispatching new chunks once an error has been recorded.
        if first_err.lock().await.is_some() {
            break;
        }
        let permit = Arc::clone(&sem)
            .acquire_owned()
            .await
            .map_err(|_| Error::pool("pipeline semaphore closed"))?;
        let exec = Arc::clone(&exec);
        let first_err = Arc::clone(&first_err);
        set.spawn(async move {
            let _permit = permit; // released on drop
            if let Err(e) = exec(chunk).await {
                let mut slot = first_err.lock().await;
                if slot.is_none() {
                    *slot = Some(e);
                }
            }
        });
    }

    // Wait for all in-flight chunks to complete.
    while set.join_next().await.is_some() {}

    match Arc::try_unwrap(first_err) {
        Ok(m) => match m.into_inner() {
            Some(e) => Err(e),
            None => Ok(()),
        },
        Err(arc) => {
            let mut guard = arc.lock().await;
            match guard.take() {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::schema::Statement;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// Maximum concurrent in-flight chunks observed by a test counter helper.
    struct ConcurrencyGauge {
        current: AtomicUsize,
        max: AtomicUsize,
    }

    impl ConcurrencyGauge {
        fn new() -> Self {
            Self {
                current: AtomicUsize::new(0),
                max: AtomicUsize::new(0),
            }
        }
        fn enter(&self) {
            let now = self.current.fetch_add(1, Ordering::SeqCst) + 1;
            self.max.fetch_max(now, Ordering::SeqCst);
        }
        fn leave(&self) {
            self.current.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn stmts(n: usize) -> Vec<Statement> {
        (0..n)
            .map(|i| Statement::new(format!("CREATE (n {{i: {}}})", i)))
            .collect()
    }

    #[test]
    fn test_chunk_statements_exact() {
        let c = chunk_statements(&stmts(10), 3);
        assert_eq!(c.len(), 4); // 3+3+3+1
        assert_eq!(c[0].len(), 3);
        assert_eq!(c[3].len(), 1);
    }

    #[test]
    fn test_chunk_statements_single_chunk() {
        let c = chunk_statements(&stmts(50), 100);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].len(), 50);
    }

    #[test]
    fn test_chunk_statements_chunk_size_one() {
        let c = chunk_statements(&stmts(5), 1);
        assert_eq!(c.len(), 5);
    }

    #[test]
    fn test_chunk_statements_zero_defaults() {
        let c = chunk_statements(&stmts(250), 0);
        assert_eq!(c.len(), 3); // 100+100+50
    }

    #[test]
    fn test_chunk_statements_empty() {
        let c = chunk_statements(&[], 10);
        assert!(c.is_empty());
    }

    #[tokio::test]
    async fn test_pipeline_drive_all_succeed() {
        let s = stmts(25);
        let res = super::pipeline_drive(&s, 10, 4, |_chunk| async { Ok(()) }).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_pipeline_drive_first_error_returned() {
        let s = stmts(30);
        // chunk size 10 => 3 chunks; the chunk containing index 0 errors.
        let res = super::pipeline_drive(&s, 10, 8, |chunk| async move {
            if chunk[0].query.contains("i: 0") {
                Err(Error::Query {
                    code: "42000".into(),
                    message: "boom".into(),
                })
            } else {
                Ok(())
            }
        })
        .await;
        let err = res.unwrap_err();
        assert!(err.to_string().contains("boom"));
    }

    #[tokio::test]
    async fn test_pipeline_drive_respects_worker_bound() {
        let s = stmts(40); // 4 chunks of 10
        let gauge = Arc::new(ConcurrencyGauge::new());
        let g = gauge.clone();
        let res = super::pipeline_drive(&s, 10, 2, move |_chunk| {
            let g = g.clone();
            async move {
                g.enter();
                tokio::time::sleep(Duration::from_millis(20)).await;
                g.leave();
                Ok(())
            }
        })
        .await;
        assert!(res.is_ok());
        assert!(
            gauge.max.load(Ordering::SeqCst) <= 2,
            "exceeded worker bound"
        );
    }

    #[tokio::test]
    async fn test_pipeline_drive_empty_ok() {
        let res = super::pipeline_drive(&[], 10, 4, |_c| async { Ok(()) }).await;
        assert!(res.is_ok());
    }
}

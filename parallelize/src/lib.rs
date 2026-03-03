//! Parallelization utilities for CPU-heavy blocking workloads.
//!
//! This crate provides async-friendly wrappers around Rayon's thread pool for offloading
//! CPU-intensive operations (EC multiplication, ECDSA signing, MAC verification) from
//! async executor threads.
//!
//! For background on async executors and blocking, see
//! [Async: What is blocking?](https://ryhl.io/blog/async-what-is-blocking/).
//!
//! See the [`cpu`] module for the primary API.

/// Module for thread-pool-based parallelization of CPU-heavy blocking workloads.
///
/// ## Zombie Task Prevention
///
/// The Rayon thread pool is sized to CPU cores for crypto operations. Callers wrap
/// tasks with timeouts (e.g., 150ms for packet decoding). When a timeout fires, the
/// async receiver is dropped, but Rayon has no native cancellation—the closure
/// continues as a "zombie" task whose result is discarded.
///
/// Under sustained load, zombie accumulation can starve the pool: timed-out tasks
/// continue occupying threads, causing later tasks to also time out. To break
/// this cycle, each spawned closure checks `tx.is_canceled()` before executing.
/// If the receiver was dropped while queued, the closure returns immediately.
///
/// ## Queue Depth Limiting
///
/// To prevent unbounded queue growth, the module tracks outstanding tasks (queued +
/// running). Use [`spawn_blocking`] or [`spawn_fifo_blocking`] which return
/// [`SpawnError::QueueFull`] when the configured limit is reached.
///
/// Set `HOPR_CPU_TASK_QUEUE_LIMIT` environment variable to enable limiting.
///
/// ## Observability
///
/// Prometheus metrics (behind the `prometheus` feature) track:
/// - **submitted**: total tasks entering the queue
/// - **completed**: tasks that delivered results to a live receiver
/// - **canceled**: tasks skipped via cooperative cancellation
/// - **orphaned**: tasks that ran but whose receiver was dropped during execution
/// - **rejected**: tasks rejected due to queue being full
/// - **queue_wait**: histogram of queue wait time
/// - **execution_time**: histogram of task execution duration
/// - **outstanding_tasks**: current queued + running tasks
/// - **queue_limit**: configured maximum (for comparison)
#[cfg(feature = "rayon")]
pub mod cpu {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use futures::channel::oneshot;

    pub use rayon;

    #[cfg(all(feature = "telemetry", not(test)))]
    use opentelemetry::{global, KeyValue, metrics::{Counter, Meter, Gauge, Histogram}};

    #[cfg(all(feature = "telemetry", not(test)))]
    lazy_static::lazy_static! {
        /// Histogram buckets for timing metrics (seconds).
        static ref TIMING_BUCKETS: &'static [f64] = &[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.15, 0.25, 0.5, 1.0];
        static ref METER: Meter = global::meter("hopr-parallelize");
        static ref TASKS_SUBMITTED: Counter<u64> = METER
            .u64_counter("hopr_rayon_tasks_submitted_total")
            .with_description("Total number of tasks submitted to the Rayon thread pool")
            .build();
        static ref TASKS_COMPLETED: Counter<u64> = METER
            .u64_counter("hopr_rayon_tasks_completed_total")
            .with_description("Total number of Rayon tasks that completed and delivered results")
            .build();
        static ref TASKS_CANCELLED: Counter<u64> = METER
            .u64_counter("hopr_rayon_tasks_cancelled_total")
            .with_description("Total number of Rayon tasks skipped because receiver was already dropped")
            .build();
        static ref TASKS_ORPHANED: Counter<u64> = METER
            .u64_counter("hopr_rayon_tasks_orphaned_total")
            .with_description("Total number of Rayon tasks whose results were discarded after completion")
            .build();
        static ref TASKS_REJECTED: Counter<u64> = METER
            .u64_counter("hopr_rayon_tasks_rejected_total")
            .with_description("Total number of tasks rejected due to queue being full")
            .build();
        static ref QUEUE_WAIT: Histogram<f64> = METER
            .f64_histogram("hopr_rayon_queue_wait_seconds")
            .with_description("Time tasks spend waiting in the Rayon queue before execution starts")
            .with_boundaries(TIMING_BUCKETS.to_vec())
            .build();
        static ref EXECUTION_TIME: Histogram<f64> = METER
            .f64_histogram("hopr_rayon_execution_seconds")
            .with_description("Time tasks spend executing in the Rayon thread pool")
            .with_boundaries(TIMING_BUCKETS.to_vec())
            .build();
        static ref OUTSTANDING_TASKS: Gauge<f64> = METER
            .f64_gauge("hopr_rayon_outstanding_tasks")
            .with_description("Current number of tasks queued or running in the Rayon pool")
            .build();
        static ref QUEUE_LIMIT_M: Gauge<f64> = METER
            .f64_gauge("hopr_rayon_queue_limit")
            .with_description("Configured maximum outstanding tasks for the Rayon thread pool")
            .build();
    }

    /// Current number of outstanding tasks (queued + running).
    static OUTSTANDING: AtomicUsize = AtomicUsize::new(0);

    lazy_static::lazy_static! {
        /// Queue limit from environment. `None` means no limit.
        static ref QUEUE_LIMIT: Option<usize> = {
            let limit = std::env::var("HOPR_CPU_TASK_QUEUE_LIMIT")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|&v| v > 0);

            #[cfg(all(feature = "telemetry", not(test)))]
            if let Some(l) = limit {
                QUEUE_LIMIT_M.record(l as f64, &[]);
            }

            limit
        };
    }

    /// Error type for spawn operations.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
    pub enum SpawnError {
        /// The queue is full and cannot accept more tasks.
        #[error("rayon queue full: {current}/{limit} tasks outstanding")]
        QueueFull {
            /// Current outstanding task count when rejection occurred.
            current: usize,
            /// Configured queue limit.
            limit: usize,
        },
    }

    /// Returns the current outstanding task count (queued + running).
    #[inline]
    pub fn outstanding_tasks() -> usize {
        OUTSTANDING.load(Ordering::Relaxed)
    }

    /// Returns the configured queue limit, or `None` if unlimited.
    #[inline]
    pub fn queue_limit() -> Option<usize> {
        *QUEUE_LIMIT
    }

    /// Guard that acquires a slot on construction and calls releases slot on drop,
    /// even if the task panics or returns early.
    struct SlotGuard;

    impl SlotGuard {
        /// Attempts to acquire a slot for a new task.
        ///
        /// Returns `Ok(())` if no limit or slot acquired, `Err(QueueFull)` if at limit.
        pub fn try_acquire_slot() -> Result<Self, SpawnError> {
            let prev = OUTSTANDING.fetch_add(1, Ordering::AcqRel);
            #[cfg(all(feature = "telemetry", not(test)))]
            OUTSTANDING_TASKS.record(1.0, &[]);

            let guard = Self;

            if let Some(limit) = *QUEUE_LIMIT {
                let new = prev + 1;
                if new > limit {
                    #[cfg(all(feature = "telemetry", not(test)))]
                    TASKS_REJECTED.add(1, &[]);

                    return Err(SpawnError::QueueFull { current: prev, limit });
                }
            }
            Ok(guard)
        }
    }

    impl Drop for SlotGuard {
        #[inline]
        fn drop(&mut self) {
            let prev = OUTSTANDING.fetch_sub(1, Ordering::AcqRel);
            debug_assert!(prev > 0, "outstanding task count underflow");
            #[cfg(all(feature = "telemetry", not(test)))]
            OUTSTANDING_TASKS.record(-1.0, &[]);
        }
    }

    /// Initialize the Rayon thread pool with the given number of threads.
    ///
    /// Also initializes the queue limit metric.
    pub fn init_thread_pool(num_threads: usize) -> Result<(), rayon::ThreadPoolBuildError> {
        let builder = rayon::ThreadPoolBuilder::new().num_threads(num_threads);

        let builder = builder.spawn_handler(|thread| {
            let mut thread_builder = std::thread::Builder::new();
            if let Some(name) = thread.name() {
                thread_builder = thread_builder.name(name.to_owned());
            }
            if let Some(stack_size) = thread.stack_size() {
                thread_builder = thread_builder.stack_size(stack_size);
            }
            thread_builder.spawn(|| {
                #[cfg(target_os = "macos")]
                unsafe {
                    // MacOS: Set the QOS class to "user initiated" to allow running on performance cores
                    libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_USER_INITIATED, 0);
                }
                thread.run()
            })?;
            Ok(())
        });

        let result = builder.build_global();
        let _ = *QUEUE_LIMIT; // Initialize limit metric
        result
    }

    /// Builds a cancellable task closure and its receiver.
    ///
    /// The closure wraps `f` with cooperative cancellation, panic catching,
    /// timing metrics, and slot tracking via guard.
    ///
    /// Note: Cooperative cancellation only prevents "queued zombies" - tasks whose
    /// receiver was dropped before execution started. If the timeout fires *after*
    /// execution begins, the task will still run to completion (counted as "orphaned").
    fn cancellable_task<R: Send + 'static>(
        f: impl FnOnce() -> R + Send + 'static,
        _operation: &'static str,
    ) -> Result<
        (
            impl FnOnce() + Send + 'static,
            oneshot::Receiver<std::thread::Result<R>>,
        ),
        SpawnError,
    > {
        let guard = SlotGuard::try_acquire_slot()?;

        let (tx, rx) = oneshot::channel();
        let submitted_at = std::time::Instant::now();

        #[cfg(all(feature = "telemetry", not(test)))]
        TASKS_SUBMITTED.add(1, &[]);

        let task = move || {
            // ensures guard is moved inside the closure, and
            // that the slot is released even on panic
            let _g = guard;

            if tx.is_canceled() {
                tracing::debug!(
                    queue_wait_ms = submitted_at.elapsed().as_millis() as u64,
                    "skipping cancelled task (receiver dropped before execution)"
                );
                #[cfg(all(feature = "telemetry", not(test)))]
                TASKS_CANCELLED.add(1, &[]);
                return;
            }

            let wait_duration = submitted_at.elapsed();
            #[cfg(all(feature = "telemetry", not(test)))]
            QUEUE_WAIT.record(wait_duration.as_secs_f64(), &[]);

            let _execution_start = std::time::Instant::now();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
            #[cfg(all(feature = "telemetry", not(test)))]
            EXECUTION_TIME.record(
                _execution_start.elapsed().as_secs_f64(),
                &[KeyValue::new("operation", _operation.to_string())],
            );

            match tx.send(result) {
                Ok(()) => {
                    #[cfg(all(feature = "telemetry", not(test)))]
                    TASKS_COMPLETED.add(1, &[]);
                },
                Err(_) => {
                    tracing::debug!(
                        queue_wait_ms = wait_duration.as_millis() as u64,
                        "receiver dropped during execution, result discarded"
                    );
                    #[cfg(all(feature = "telemetry", not(test)))]
                    TASKS_ORPHANED.add(1, &[]);
                }
            }
        };

        Ok((task, rx))
    }

    /// Spawn a blocking function on the Rayon thread pool (LIFO scheduling).
    ///
    /// Uses Rayon's default LIFO scheduling for the thread's local queue.
    ///
    /// Includes cooperative cancellation: if the receiver is dropped before the
    /// task starts (e.g., timeout), the task is skipped without executing.
    ///
    /// # Errors
    ///
    /// Returns [`SpawnError::QueueFull`] if the outstanding task count exceeds the limit.
    pub async fn spawn_blocking<R: Send + 'static>(
        f: impl FnOnce() -> R + Send + 'static,
        operation: &'static str,
    ) -> Result<R, SpawnError> {
        let (task, rx) = cancellable_task(f, operation)?;
        rayon::spawn(task);
        Ok(rx
            .await
            .expect("rayon task channel closed unexpectedly")
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic)))
    }

    /// Spawn a blocking function on the Rayon thread pool (FIFO scheduling).
    ///
    /// Uses FIFO scheduling which prevents starvation of older tasks. This is the
    /// preferred variant for packet decoding and similar ordered workloads.
    ///
    /// Includes cooperative cancellation: if the receiver is dropped before the
    /// task starts (e.g., timeout), the task is skipped without executing.
    ///
    /// # Errors
    ///
    /// Returns [`SpawnError::QueueFull`] if the outstanding task count exceeds the limit.
    pub async fn spawn_fifo_blocking<R: Send + 'static>(
        f: impl FnOnce() -> R + Send + 'static,
        operation: &'static str,
    ) -> Result<R, SpawnError> {
        let (task, rx) = cancellable_task(f, operation)?;
        rayon::spawn_fifo(task);
        Ok(rx
            .await
            .expect("rayon task channel closed unexpectedly")
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic)))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicU32, Ordering},
        },
        time::Duration,
    };

    use futures::FutureExt;
    use serial_test::serial;

    use super::cpu;

    #[tokio::test]
    #[serial]
    async fn spawn_blocking_returns_result() {
        let result = cpu::spawn_blocking(|| 42, "test").await.unwrap();
        assert_eq!(result, 42);
    }

    #[tokio::test]
    #[serial]
    async fn spawn_fifo_blocking_returns_result() {
        let result = cpu::spawn_fifo_blocking(|| "hello", "test").await.unwrap();
        assert_eq!(result, "hello");
    }

    #[cfg(panic = "unwind")]
    #[tokio::test]
    #[serial]
    async fn spawn_blocking_propagates_panic() {
        let result = std::panic::AssertUnwindSafe(async {
            cpu::spawn_blocking(
                || {
                    panic!("test panic");
                },
                "test",
            )
            .await
            .unwrap()
        })
        .catch_unwind()
        .await;
        assert!(result.is_err(), "should propagate panic from Rayon task");
    }

    #[tokio::test]
    #[serial]
    async fn cancelled_tasks_are_skipped_via_cooperative_cancellation() {
        let initial_outstanding = cpu::outstanding_tasks();
        let executed_count = Arc::new(AtomicU32::new(0));

        for _ in 0..100 {
            let count = executed_count.clone();
            let fut = cpu::spawn_fifo_blocking(
                move || {
                    count.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(50));
                },
                "test",
            );
            let _ = fut.now_or_never();
        }

        let start = std::time::Instant::now();
        let result = cpu::spawn_fifo_blocking(|| 42, "test").await.unwrap();
        let elapsed = start.elapsed();

        assert_eq!(result, 42);
        assert!(
            elapsed < Duration::from_secs(2),
            "Task took {elapsed:?} - cancelled tasks may not be getting skipped"
        );

        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if cpu::outstanding_tasks() == initial_outstanding {
                break;
            }
        }

        let executed = executed_count.load(Ordering::SeqCst);
        assert!(
            executed < 50,
            "Expected most tasks to be skipped by cancellation, but {executed}/100 executed"
        );
    }

    #[tokio::test]
    #[serial]
    async fn pool_recovers_after_cancelled_burst() {
        let initial_outstanding = cpu::outstanding_tasks();

        for _ in 0..50 {
            let fut = cpu::spawn_fifo_blocking(
                || {
                    std::thread::sleep(Duration::from_millis(100));
                },
                "test",
            );
            let _ = fut.now_or_never();
        }

        tokio::time::sleep(Duration::from_millis(300)).await;

        for i in 0..10 {
            let start = std::time::Instant::now();
            let result = cpu::spawn_fifo_blocking(move || i * 2, "test").await.unwrap();
            let elapsed = start.elapsed();

            assert_eq!(result, i * 2);
            assert!(
                elapsed < Duration::from_millis(500),
                "Recovery task {i} took {elapsed:?} - pool may still be starved"
            );
        }

        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if cpu::outstanding_tasks() == initial_outstanding {
                break;
            }
        }
    }

    #[tokio::test]
    #[serial]
    async fn outstanding_tasks_tracking() {
        let initial = cpu::outstanding_tasks();

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let barrier_clone = barrier.clone();

        let handle = tokio::spawn(async move {
            cpu::spawn_fifo_blocking(
                move || {
                    barrier_clone.wait();
                    42
                },
                "test",
            )
            .await
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let during = cpu::outstanding_tasks();
        assert!(
            during > initial,
            "Outstanding should increase: initial={initial}, during={during}"
        );

        barrier.wait();

        let result = handle.await.unwrap();
        assert_eq!(result.unwrap(), 42);

        tokio::time::sleep(Duration::from_millis(50)).await;

        let after = cpu::outstanding_tasks();
        assert_eq!(after, initial, "Outstanding should return to initial after completion");
    }

    #[tokio::test]
    #[serial]
    async fn outstanding_decrements_on_cancellation() {
        let initial = cpu::outstanding_tasks();

        for _ in 0..10 {
            let fut = cpu::spawn_fifo_blocking(
                || {
                    std::thread::sleep(Duration::from_millis(100));
                },
                "test",
            );
            let _ = fut.now_or_never();
        }

        tokio::time::sleep(Duration::from_millis(500)).await;

        let after = cpu::outstanding_tasks();
        assert_eq!(
            after, initial,
            "Outstanding should return to initial after cancelled tasks drain"
        );
    }
}

use std::collections::VecDeque;
use std::fmt;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

const FIXED_WORKER_PANIC_MESSAGE: &str = "worker panic";

/// Cooperative cancellation flag for worker-pool tasks.
#[derive(Clone, Debug, Default)]
pub struct WorkerCancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl WorkerCancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// Error surface for the deterministic worker-pool primitive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkerPoolError<E> {
    Cancelled,
    Panic(String),
    Task(E),
}

impl<E> fmt::Display for WorkerPoolError<E>
where
    E: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => write!(f, "worker cancelled"),
            Self::Panic(msg) => write!(f, "worker panic: {msg}"),
            Self::Task(err) => err.fmt(f),
        }
    }
}

impl<E> std::error::Error for WorkerPoolError<E> where E: std::error::Error + 'static {}

/// Pool-wide execution failures detected before or outside task execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkerPoolRunError {
    InvalidMaxTasks,
    TooManyTasks { task_count: usize, max_tasks: usize },
    QueuePoisoned,
    ResultCollectionIncomplete { expected: usize, received: usize },
}

impl fmt::Display for WorkerPoolRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMaxTasks => write!(f, "worker pool max_tasks must be positive"),
            Self::TooManyTasks {
                task_count,
                max_tasks,
            } => write!(
                f,
                "worker pool task count {task_count} exceeds configured limit {max_tasks}"
            ),
            Self::QueuePoisoned => write!(f, "worker queue poisoned"),
            Self::ResultCollectionIncomplete { expected, received } => write!(
                f,
                "worker result collection incomplete: expected {expected}, received {received}"
            ),
        }
    }
}

impl std::error::Error for WorkerPoolRunError {}

/// Ordered outcome for one submitted task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerResult<R, E> {
    pub value: Option<R>,
    pub error: Option<WorkerPoolError<E>>,
}

impl<R, E> WorkerResult<R, E> {
    fn success(value: R) -> Self {
        Self {
            value: Some(value),
            error: None,
        }
    }

    fn failure(error: WorkerPoolError<E>) -> Self {
        Self {
            value: None,
            error: Some(error),
        }
    }
}

/// Single-use bounded deterministic worker pool for read-only consensus jobs.
///
/// The pool does not infer safe task counts on its own. Callers must provide
/// a consensus-derived `max_tasks` limit so adversarial inputs cannot inflate
/// ordered result buffers beyond the intended block-scoped surface.
pub struct WorkerPool<F> {
    pub max_workers: usize,
    pub max_tasks: usize,
    pub func: F,
}

impl<F> WorkerPool<F> {
    pub fn new(max_workers: usize, max_tasks: usize, func: F) -> Self {
        Self {
            max_workers,
            max_tasks,
            func,
        }
    }

    pub fn run<T, R, E>(
        &self,
        token: &WorkerCancellationToken,
        tasks: Vec<T>,
    ) -> Result<Vec<WorkerResult<R, E>>, WorkerPoolRunError>
    where
        T: Send,
        R: Send,
        E: Send,
        F: Fn(&WorkerCancellationToken, T) -> Result<R, E> + Sync,
    {
        let task_count = tasks.len();
        if task_count == 0 {
            return Ok(Vec::new());
        }
        if self.max_tasks == 0 {
            return Err(WorkerPoolRunError::InvalidMaxTasks);
        }
        if task_count > self.max_tasks {
            return Err(WorkerPoolRunError::TooManyTasks {
                task_count,
                max_tasks: self.max_tasks,
            });
        }

        let worker_count = normalized_worker_count(self.max_workers, task_count);
        if task_count == 1 {
            let task = tasks.into_iter().next().expect("single task exists");
            return Ok(vec![exec_task(&self.func, token, task)]);
        }

        let queue = Arc::new(Mutex::new(
            tasks.into_iter().enumerate().collect::<VecDeque<_>>(),
        ));
        let (tx, rx) = mpsc::channel::<(usize, WorkerResult<R, E>)>();
        let hard_failure = Arc::new(Mutex::new(None::<WorkerPoolRunError>));
        let mut results = std::iter::repeat_with(|| None)
            .take(task_count)
            .collect::<Vec<Option<WorkerResult<R, E>>>>();
        let mut received = 0usize;

        thread::scope(|scope| {
            for _ in 0..worker_count {
                let queue = Arc::clone(&queue);
                let tx = tx.clone();
                let token = token.clone();
                let func = &self.func;
                let hard_failure = Arc::clone(&hard_failure);
                scope.spawn(move || loop {
                    let next = {
                        let Ok(mut guard) = queue.lock() else {
                            record_run_error(&hard_failure, WorkerPoolRunError::QueuePoisoned);
                            break;
                        };
                        guard.pop_front()
                    };
                    let Some((idx, task)) = next else {
                        break;
                    };
                    let result = exec_task(func, &token, task);
                    if tx.send((idx, result)).is_err() {
                        break;
                    }
                });
            }
            drop(tx);
            for (idx, result) in rx {
                results[idx] = Some(result);
                received += 1;
            }
        });

        if let Some(err) = take_run_error(&hard_failure) {
            return Err(err);
        }
        if received != task_count {
            return Err(WorkerPoolRunError::ResultCollectionIncomplete {
                expected: task_count,
                received,
            });
        }

        results
            .into_iter()
            .map(|item| {
                item.ok_or(WorkerPoolRunError::ResultCollectionIncomplete {
                    expected: task_count,
                    received,
                })
            })
            .collect::<Result<Vec<_>, _>>()
    }
}

pub fn run_worker_pool<T, R, E, F>(
    token: &WorkerCancellationToken,
    max_workers: usize,
    max_tasks: usize,
    tasks: Vec<T>,
    func: F,
) -> Result<Vec<WorkerResult<R, E>>, WorkerPoolRunError>
where
    T: Send,
    R: Send,
    E: Send,
    F: Fn(&WorkerCancellationToken, T) -> Result<R, E> + Sync,
{
    WorkerPool::new(max_workers, max_tasks, func).run(token, tasks)
}

pub fn first_error<R, E>(results: &[WorkerResult<R, E>]) -> Option<&WorkerPoolError<E>> {
    results.iter().find_map(|result| result.error.as_ref())
}

pub fn collect_values<R, E>(
    results: Vec<WorkerResult<R, E>>,
) -> Result<Vec<R>, WorkerPoolError<E>> {
    let mut values = Vec::with_capacity(results.len());
    for result in results {
        if let Some(err) = result.error {
            return Err(err);
        }
        values.push(result.value.expect("successful result must hold value"));
    }
    Ok(values)
}

fn normalized_worker_count(max_workers: usize, task_count: usize) -> usize {
    let mut workers = max_workers;
    if workers == 0 {
        workers = thread::available_parallelism()
            .map(|v| v.get())
            .unwrap_or(1)
            .max(1);
    }
    workers.min(task_count).max(1)
}

fn exec_task<T, R, E, F>(func: &F, token: &WorkerCancellationToken, task: T) -> WorkerResult<R, E>
where
    F: Fn(&WorkerCancellationToken, T) -> Result<R, E>,
{
    if token.is_cancelled() {
        return WorkerResult::failure(WorkerPoolError::Cancelled);
    }

    match panic::catch_unwind(AssertUnwindSafe(|| func(token, task))) {
        Ok(Ok(value)) => WorkerResult::success(value),
        Ok(Err(err)) => WorkerResult::failure(WorkerPoolError::Task(err)),
        Err(panic_payload) => WorkerResult::failure(WorkerPoolError::Panic(
            panic_payload_to_string(panic_payload),
        )),
    }
}

fn panic_payload_to_string(_: Box<dyn std::any::Any + Send>) -> String {
    FIXED_WORKER_PANIC_MESSAGE.to_string()
}

fn record_run_error(target: &Mutex<Option<WorkerPoolRunError>>, err: WorkerPoolRunError) {
    if let Ok(mut guard) = target.lock() {
        if guard.is_none() {
            *guard = Some(err);
        }
    }
}

fn take_run_error(source: &Mutex<Option<WorkerPoolRunError>>) -> Option<WorkerPoolRunError> {
    source.lock().ok().and_then(|mut guard| guard.take())
}

#[cfg(test)]
mod tests {
    use super::{
        collect_values, first_error, run_worker_pool, WorkerCancellationToken, WorkerPool,
        WorkerPoolError, WorkerPoolRunError, FIXED_WORKER_PANIC_MESSAGE,
    };
    use std::panic;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    fn int_identity(_: &WorkerCancellationToken, value: usize) -> Result<usize, String> {
        Ok(value)
    }

    fn int_double(_: &WorkerCancellationToken, value: usize) -> Result<usize, String> {
        Ok(value * 2)
    }

    fn fail_odd(_: &WorkerCancellationToken, value: usize) -> Result<usize, String> {
        if value % 2 == 1 {
            return Err(format!("odd: {value}"));
        }
        Ok(value)
    }

    #[test]
    fn worker_pool_empty() {
        let token = WorkerCancellationToken::new();
        let pool = WorkerPool::new(4, 8, int_identity);
        let results: Vec<_> = pool.run::<_, _, String>(&token, Vec::new()).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn worker_pool_single_task() {
        let token = WorkerCancellationToken::new();
        let pool = WorkerPool::new(4, 8, int_double);
        let results = pool.run(&token, vec![21usize]).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, Some(42));
        assert_eq!(results[0].error, None);
    }

    #[test]
    fn worker_pool_multiple_tasks_preserve_order() {
        let token = WorkerCancellationToken::new();
        let pool = WorkerPool::new(2, 8, int_double);
        let tasks = vec![1usize, 2, 3, 4, 5];
        let results = pool.run(&token, tasks.clone()).unwrap();
        assert_eq!(results.len(), tasks.len());
        for (idx, result) in results.iter().enumerate() {
            assert_eq!(result.error, None, "task {idx} unexpectedly failed");
            assert_eq!(result.value, Some(tasks[idx] * 2));
        }
    }

    #[test]
    fn worker_pool_task_errors_preserve_index_order() {
        let token = WorkerCancellationToken::new();
        let pool = WorkerPool::new(4, 8, fail_odd);
        let tasks = vec![2usize, 3, 4, 5, 6];
        let results = pool.run(&token, tasks).unwrap();

        assert_eq!(results[0].value, Some(2));
        assert_eq!(results[0].error, None);
        assert_eq!(
            results[1].error,
            Some(WorkerPoolError::Task("odd: 3".to_string()))
        );
        assert_eq!(results[2].value, Some(4));
        assert_eq!(results[2].error, None);
        assert_eq!(
            results[3].error,
            Some(WorkerPoolError::Task("odd: 5".to_string()))
        );
        assert_eq!(results[4].value, Some(6));
        assert_eq!(results[4].error, None);
    }

    #[test]
    fn worker_pool_zero_workers_defaults_to_parallelism() {
        let token = WorkerCancellationToken::new();
        let pool = WorkerPool::new(0, 16, int_identity);
        let tasks = (0usize..10).collect::<Vec<_>>();
        let results = pool.run(&token, tasks).unwrap();
        for (idx, result) in results.iter().enumerate() {
            assert_eq!(result.error, None);
            assert_eq!(result.value, Some(idx));
        }
    }

    #[test]
    fn worker_pool_workers_capped_at_task_count() {
        let token = WorkerCancellationToken::new();
        let current = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let pool = WorkerPool::new(100, 8, {
            let current = Arc::clone(&current);
            let max_seen = Arc::clone(&max_seen);
            move |_: &WorkerCancellationToken, value: usize| -> Result<usize, String> {
                let now = current.fetch_add(1, Ordering::SeqCst) + 1;
                max_seen.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(10));
                current.fetch_sub(1, Ordering::SeqCst);
                Ok(value)
            }
        });

        let _ = pool.run(&token, vec![1usize, 2, 3]).unwrap();
        assert!(max_seen.load(Ordering::SeqCst) <= 3);
    }

    #[test]
    fn worker_pool_panic_recovery_keeps_other_tasks_running() {
        let token = WorkerCancellationToken::new();
        let pool = WorkerPool::new(2, 8, |_: &WorkerCancellationToken, value: usize| {
            if value == 3 {
                panic!("task 3 panicked");
            }
            Ok::<usize, String>(value * 10)
        });
        let tasks = vec![1usize, 2, 3, 4, 5];
        let results = pool.run(&token, tasks.clone()).unwrap();

        assert_eq!(
            results[2].error,
            Some(WorkerPoolError::Panic(
                FIXED_WORKER_PANIC_MESSAGE.to_string()
            ))
        );
        for (idx, result) in results.iter().enumerate() {
            if idx == 2 {
                continue;
            }
            assert_eq!(result.error, None);
            assert_eq!(result.value, Some(tasks[idx] * 10));
        }
    }

    #[test]
    fn worker_pool_context_cancellation_marks_unstarted_tasks() {
        let token = WorkerCancellationToken::new();
        let pool = WorkerPool::new(1, 8, {
            let token = token.clone();
            move |task_token: &WorkerCancellationToken, value: usize| -> Result<usize, String> {
                if value == 2 {
                    token.cancel();
                    return Ok(value);
                }
                if task_token.is_cancelled() {
                    return Err("cancelled".to_string());
                }
                Ok(value * 10)
            }
        });

        let results = pool.run(&token, vec![1usize, 2, 3, 4, 5]).unwrap();
        assert_eq!(results[0].value, Some(10));
        assert_eq!(results[0].error, None);
        assert_eq!(results[1].value, Some(2));
        assert_eq!(results[1].error, None);
        for result in results.iter().skip(2) {
            assert_eq!(result.value, None);
            assert_eq!(result.error, Some(WorkerPoolError::Cancelled));
        }
    }

    #[test]
    fn worker_pool_already_cancelled_token_short_circuits_all_tasks() {
        let token = WorkerCancellationToken::new();
        token.cancel();
        let pool = WorkerPool::new(4, 8, int_identity);
        let results = pool.run(&token, vec![1usize, 2, 3]).unwrap();
        for result in results {
            assert_eq!(result.value, None);
            assert_eq!(result.error, Some(WorkerPoolError::Cancelled));
        }
    }

    #[test]
    fn worker_pool_run_func_helper() {
        let token = WorkerCancellationToken::new();
        let results = run_worker_pool(&token, 2, 8, vec![10usize, 20, 30], int_double).unwrap();
        let values = collect_values(results).expect("all tasks should succeed");
        assert_eq!(values, vec![20usize, 40, 60]);
    }

    #[test]
    fn worker_pool_first_error_returns_lowest_index_error() {
        let mut results = vec![
            super::WorkerResult::success(1usize),
            super::WorkerResult::success(2usize),
            super::WorkerResult::success(3usize),
        ];
        assert_eq!(first_error(&results), None);

        results[2] = super::WorkerResult::failure(WorkerPoolError::Task("fail at 2".to_string()));
        assert_eq!(
            first_error(&results),
            Some(&WorkerPoolError::Task("fail at 2".to_string()))
        );

        results[0] = super::WorkerResult::failure(WorkerPoolError::Task("fail at 0".to_string()));
        assert_eq!(
            first_error(&results),
            Some(&WorkerPoolError::Task("fail at 0".to_string()))
        );
    }

    #[test]
    fn worker_pool_collect_values_returns_first_error() {
        let ok = vec![
            super::WorkerResult::<usize, String>::success(10usize),
            super::WorkerResult::<usize, String>::success(20usize),
            super::WorkerResult::<usize, String>::success(30usize),
        ];
        assert_eq!(collect_values(ok).unwrap(), vec![10usize, 20, 30]);

        let bad = vec![
            super::WorkerResult::<usize, String>::success(10usize),
            super::WorkerResult::<usize, String>::failure(WorkerPoolError::Task("bad".to_string())),
            super::WorkerResult::<usize, String>::success(30usize),
        ];
        assert_eq!(
            collect_values(bad),
            Err(WorkerPoolError::Task("bad".to_string()))
        );
    }

    #[test]
    fn worker_pool_result_order_is_deterministic_across_runs() {
        for _ in 0..10 {
            let token = WorkerCancellationToken::new();
            let pool = WorkerPool::new(4, 32, |_: &WorkerCancellationToken, value: usize| {
                if value.is_multiple_of(3) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Ok::<usize, String>(value * value)
            });
            let tasks = (0usize..20).collect::<Vec<_>>();
            let results = pool.run(&token, tasks.clone()).unwrap();
            for (idx, result) in results.iter().enumerate() {
                assert_eq!(result.error, None);
                assert_eq!(result.value, Some(tasks[idx] * tasks[idx]));
            }
        }
    }

    #[test]
    fn worker_pool_bounded_concurrency() {
        const MAX_WORKERS: usize = 3;
        let token = WorkerCancellationToken::new();
        let current = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let pool = WorkerPool::new(MAX_WORKERS, 32, {
            let current = Arc::clone(&current);
            let max_seen = Arc::clone(&max_seen);
            move |_: &WorkerCancellationToken, value: usize| -> Result<usize, String> {
                let now = current.fetch_add(1, Ordering::SeqCst) + 1;
                max_seen.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(20));
                current.fetch_sub(1, Ordering::SeqCst);
                Ok(value)
            }
        });

        let tasks = (0usize..20).collect::<Vec<_>>();
        let _ = pool.run(&token, tasks).unwrap();
        assert!(max_seen.load(Ordering::SeqCst) <= MAX_WORKERS);
    }

    #[test]
    fn worker_pool_large_batch() {
        let token = WorkerCancellationToken::new();
        let tasks = (0usize..1000).collect::<Vec<_>>();
        let pool = WorkerPool::new(8, 1000, int_double);
        let results = pool.run(&token, tasks.clone()).unwrap();
        assert_eq!(results.len(), tasks.len());
        for (idx, result) in results.iter().enumerate() {
            assert_eq!(result.error, None);
            assert_eq!(result.value, Some(tasks[idx] * 2));
        }
    }

    #[test]
    fn worker_pool_rejects_zero_max_tasks() {
        let token = WorkerCancellationToken::new();
        let pool = WorkerPool::new(4, 0, int_identity);
        assert_eq!(
            pool.run(&token, vec![1usize, 2, 3]),
            Err(WorkerPoolRunError::InvalidMaxTasks)
        );
    }

    #[test]
    fn worker_pool_rejects_task_count_over_limit() {
        let token = WorkerCancellationToken::new();
        let pool = WorkerPool::new(4, 2, int_identity);
        assert_eq!(
            pool.run(&token, vec![1usize, 2, 3]),
            Err(WorkerPoolRunError::TooManyTasks {
                task_count: 3,
                max_tasks: 2,
            })
        );
    }

    #[test]
    fn worker_pool_non_string_panic_uses_fixed_message() {
        let token = WorkerCancellationToken::new();
        let pool = WorkerPool::new(1, 1, |_: &WorkerCancellationToken, _value: usize| {
            panic::panic_any(7usize);
            #[allow(unreachable_code)]
            Ok::<usize, String>(0)
        });

        let results = pool.run(&token, vec![1usize]).unwrap();
        assert_eq!(
            results[0].error,
            Some(WorkerPoolError::Panic(
                FIXED_WORKER_PANIC_MESSAGE.to_string()
            ))
        );
    }

    #[test]
    fn worker_pool_error_display_variants() {
        assert_eq!(
            WorkerPoolError::<String>::Cancelled.to_string(),
            "worker cancelled"
        );
        assert_eq!(
            WorkerPoolError::<String>::Panic(FIXED_WORKER_PANIC_MESSAGE.to_string()).to_string(),
            "worker panic: worker panic"
        );
        assert_eq!(
            WorkerPoolError::<String>::Task("task failed".to_string()).to_string(),
            "task failed"
        );
    }

    #[test]
    fn worker_pool_run_error_display_variants() {
        assert_eq!(
            WorkerPoolRunError::InvalidMaxTasks.to_string(),
            "worker pool max_tasks must be positive"
        );
        assert_eq!(
            WorkerPoolRunError::TooManyTasks {
                task_count: 7,
                max_tasks: 3,
            }
            .to_string(),
            "worker pool task count 7 exceeds configured limit 3"
        );
        assert_eq!(
            WorkerPoolRunError::QueuePoisoned.to_string(),
            "worker queue poisoned"
        );
        assert_eq!(
            WorkerPoolRunError::ResultCollectionIncomplete {
                expected: 5,
                received: 4,
            }
            .to_string(),
            "worker result collection incomplete: expected 5, received 4"
        );
    }
}

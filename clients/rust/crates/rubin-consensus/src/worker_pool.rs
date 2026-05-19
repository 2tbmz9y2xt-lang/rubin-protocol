use std::collections::VecDeque;
use std::fmt;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
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
            Self::Cancelled => write!(f, "context canceled"),
            Self::Panic(msg) => write!(f, "{msg}"),
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

        let queue = Mutex::new(tasks.into_iter().enumerate().collect::<VecDeque<_>>());
        let results = (0..task_count)
            .map(|_| Mutex::new(None::<WorkerResult<R, E>>))
            .collect::<Vec<_>>();

        thread::scope(|scope| {
            for _ in 0..worker_count {
                let token = token.clone();
                let func = &self.func;
                let queue = &queue;
                let results = &results;
                scope.spawn(move || loop {
                    let next = {
                        let mut guard = lock_recover(queue);
                        guard.pop_front()
                    };
                    let Some((idx, task)) = next else {
                        break;
                    };
                    let result = exec_task(func, &token, task);
                    *lock_recover(&results[idx]) = Some(result);
                });
            }
        });

        Ok(results
            .into_iter()
            .map(|slot| {
                let slot = slot.into_inner().unwrap_or_else(PoisonError::into_inner);
                slot.unwrap_or_else(worker_result_missing_failure)
            })
            .collect())
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

fn lock_recover<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn worker_result_missing_failure<R, E>() -> WorkerResult<R, E> {
    WorkerResult::failure(WorkerPoolError::Panic(
        FIXED_WORKER_PANIC_MESSAGE.to_string(),
    ))
}

#[cfg(test)]
#[path = "tests/worker_pool.rs"]
mod tests;

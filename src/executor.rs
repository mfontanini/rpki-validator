use std::cmp::Ordering;
use std::collections::binary_heap::BinaryHeap;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{Sender, Receiver, channel, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

pub trait Work {
    // Returns next execution time
    fn execute(&mut self) -> Option<Instant>;
}

type WorkPtr = Box<Work + Send>;

struct Worker {

}

impl Worker {
    fn start_work(work_receiver: Arc<Mutex<Receiver<WorkPtr>>>,
                  new_work_sender: Sender<ScheduledWork>) {
        thread::spawn(move || {
            loop {
                let work = work_receiver.lock().unwrap().recv();
                let result = work.ok().map(|mut work| {
                    if let Some(execution_time) = work.execute() {
                        info!("Re-scheduling work for {:?}", execution_time);
                        new_work_sender.send(ScheduledWork::new(work, execution_time)).ok()
                    }
                    else {
                        Some(())
                    }
                });
                if result.is_none() {
                    break;
                }
            }
        });
    }
}

struct ScheduledWork {
    work: WorkPtr,
    execution_time: Instant,
}

impl ScheduledWork {
    fn new(work: WorkPtr, execution_time: Instant) -> ScheduledWork {
        ScheduledWork {
            work,
            execution_time,
        }
    }

    fn execution_time(&self) -> &Instant {
        &self.execution_time
    }

    fn work(self) -> WorkPtr {
        self.work
    }
}

pub struct Executor {
    new_work_sender: Sender<ScheduledWork>,
}

impl Executor {
    pub fn new(num_workers: usize) -> Self {
        let (new_work_tx, new_work_rx) = channel();
        let (ready_work_tx, ready_work_rx) = channel();
        let ready_work_rx = Arc::new(Mutex::new(ready_work_rx));
        for _ in 0..num_workers {
            Worker::start_work(ready_work_rx.clone(), new_work_tx.clone());
        }
        thread::spawn(move || {
            let executor_impl = ExecutorImpl::new(new_work_rx, ready_work_tx);
            executor_impl.work();
        });
        Executor {
            new_work_sender: new_work_tx,
        }
    }

    pub fn add_work(&mut self, work: WorkPtr, execution_time: Instant) {
        let new_work = ScheduledWork::new(work, execution_time);
        self.new_work_sender.send(new_work).expect("Failed to write work into channel");
    }
}

struct ExecutorImpl {
    new_work_receiver: Receiver<ScheduledWork>,
    ready_work_sender: Sender<WorkPtr>,
    works: BinaryHeap<ScheduledWork>,
}

impl Ord for ScheduledWork {
    fn cmp(&self, other: &ScheduledWork) -> Ordering {
        other.execution_time().cmp(&self.execution_time())
    }
}

impl PartialOrd for ScheduledWork {
    fn partial_cmp(&self, other: &ScheduledWork) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for ScheduledWork {
    fn eq(&self, other: &ScheduledWork) -> bool {
        self.execution_time() == other.execution_time()
    }
}

impl Eq for ScheduledWork {

}

impl ExecutorImpl {
    const MAX_TIMEOUT: Duration = Duration::from_secs(1);

    fn new(new_work_receiver: Receiver<ScheduledWork>,
           ready_work_sender: Sender<WorkPtr>)
        -> Self 
    {
        ExecutorImpl {
            new_work_receiver,
            ready_work_sender,
            works: BinaryHeap::new(),
        }
    }

    fn work(mut self) {
        loop {
            // Process any works which are ready
            self.process_scheduled_works();

            let timeout = match self.works.peek() {
                Some(new_work) => new_work.execution_time - Instant::now(),
                None => Self::MAX_TIMEOUT,
            };
            match self.new_work_receiver.recv_timeout(timeout) {
                Ok(new_work) => self.works.push(new_work),
                Err(RecvTimeoutError::Disconnected) => {
                    info!("Executor failed to read from channel, stopping it");
                    break;
                },
                // We simply hit a timeout. Keep retrying
                Err(RecvTimeoutError::Timeout) => (),
            }
        }
    }

    fn process_scheduled_works(&mut self) {
        loop {
            let is_ready = match self.works.peek() {
                Some(scheduled_work) => scheduled_work.execution_time() <= &Instant::now(),
                None => false,
            };
            if is_ready {
                debug!("Found work ready to be executed, forwarding to worker");
                let scheduled_work = self.works.pop().unwrap();
                if self.ready_work_sender.send(scheduled_work.work()).is_err() {
                    info!("Failed to send ready work");
                }
            }
            else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    #[derive(Clone)]
    struct DummyWork {

    }

    impl Work for DummyWork {
        fn execute(&mut self) -> Option<Instant> {
            None
        }
    }

    impl fmt::Debug for ScheduledWork {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "ScheduledWork(execution_time={:?})", self.execution_time)
        }
    }

    #[test]
    fn new_work_compare() {
        let base_instant = Instant::now();
        let work = Box::new(DummyWork{});
        let build = |instant| {
            ScheduledWork::new(work.clone(), instant)
        };

        assert_eq!(
            build(base_instant).cmp(&build(base_instant + Duration::from_secs(1))),
            Ordering::Greater,
        );
        assert_eq!(
            build(base_instant + Duration::from_secs(1)).cmp(&build(base_instant)),
            Ordering::Less,
        );
        assert_eq!(
            build(base_instant).cmp(&build(base_instant)),
            Ordering::Equal,
        );

        let mut binary_heap = BinaryHeap::new();
        let mut instants = vec![];
        for i in 0..5 {
            let instant = base_instant + Duration::from_secs(i);
            instants.push(instant.clone());
            binary_heap.push(build(instant));
        }
        assert_eq!(binary_heap.len(), instants.len());

        for instant in instants {
            assert_eq!(binary_heap.pop().unwrap().execution_time, instant);
        }
    }
}

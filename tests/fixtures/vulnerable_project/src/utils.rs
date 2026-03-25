//! Utility module with additional vulnerable calls.

use smallvec::SmallVec;
use tokio::runtime::task::JoinHandle;

pub fn process_data(items: &[u8]) {
    // Case 3: Method call on constructor-inferred type (HIGH with type tracking)
    let mut vec = SmallVec::new();
    vec.insert_many(0, items.iter().copied());

    // Case 4: Method call on typed parameter (HIGH with type tracking)
    cancel_task(get_handle());
}

fn cancel_task(handle: JoinHandle) {
    handle.abort();
}

fn get_handle() -> JoinHandle {
    todo!()
}

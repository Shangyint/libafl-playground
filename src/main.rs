// adapt from libafl/fuzzers/babyfuzzer

use std::{io::Bytes, path::PathBuf};

use libafl::monitors::SimpleMonitor;
use libafl::{
    bolts::{current_nanos, rands::StdRand, tuples::tuple_list, AsSlice},
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};
mod toyfuzzer;

static mut SIGNALS: [u8; 16] = [0; 16];

fn signals_set(idx: usize) {
    unsafe { SIGNALS[idx] = 1 };
}

pub fn main() {
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        signals_set(0);
        if !buf.is_empty() && buf[0] == b'a' {
            signals_set(1);
            if buf.len() > 1 && buf[1] == b'b' {
                signals_set(2);
                if buf.len() > 2 && buf[2] == b'c' {
                    #[cfg(unix)]
                    panic!("Artificial bug triggered =)");
                }
            }
        }
        ExitKind::Ok
    };

    // let observer = unsafe { StdMapObserver::new_from_ptr("signals", SIGNALS.as_mut_ptr(), SIGNALS.len()) };

    // let mut feedback = MaxMapFeedback::new(&observer);

    let mut objective = CrashFeedback::new();

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::new(),
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        &mut (),
        &mut objective,
    )
    .unwrap();

    let mon = SimpleMonitor::new(|s| println!("{}", s));

            let mut mgr = SimpleEventManager::new(mon);

    let scheduler = QueueScheduler::new();

    let mut fuzzer = StdFuzzer::new(scheduler, (), objective);

    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor");

    let mut generator = RandPrintablesGenerator::new(32);
    state
        .generate_initial_inputs_forced(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");

    // println!("{}", state.generate_initial_inputs_forced(fuzzer, executor, generator, manager, num));

    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    
    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");

    println!("Hello, LibAFL!");
}


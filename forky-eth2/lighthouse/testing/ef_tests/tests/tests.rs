#![cfg(feature = "ef_tests")]

use ef_tests::*;
use types::*;

#[test]
fn fork_choice_forky() {
    ForkChoiceHandler::<MainnetEthSpec>::new("forky").run();
}
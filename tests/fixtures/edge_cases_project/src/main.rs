mod aliased;
mod commented;
mod false_positive;
mod grouped;

fn main() {
    aliased::run();
    grouped::run();
    commented::run();
    false_positive::run();
}

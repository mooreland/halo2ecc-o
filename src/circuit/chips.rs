pub mod native_chip;
pub mod bit_chip;
pub mod int_chip;

#[macro_export]
macro_rules! pair {
    ($a:expr, $b:expr) => {
        ($a as _, $b)
    };
}

pub mod native_chip;
pub mod bit_chip;
pub mod int_chip;
pub mod ecc_chip;
pub mod msm_chip;

#[macro_export]
macro_rules! pair {
    ($a:expr, $b:expr) => {
        ($a as &dyn crate::assign::MayAssignedValue<_>, $b)
    };
}

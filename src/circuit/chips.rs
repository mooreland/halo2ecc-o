pub mod bit_chip;
pub mod ecc_chip;
pub mod int_chip;
pub mod keccak_chip;
pub mod msm_chip;
pub mod native_chip;
pub mod pairing_chip;

#[macro_export]
macro_rules! pair {
    ($a:expr, $b:expr) => {
        ($a as &dyn crate::assign::MayAssignedValue<_>, $b)
    };
}

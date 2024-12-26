use halo2_proofs::arithmetic::{BaseExt, FieldExt};
use halo2_proofs::circuit::Cell;

const MAX_LIMBS: usize = 3;

#[derive(Copy, Clone, Debug)]
pub struct AssignedValue<N: FieldExt> {
    pub(crate) value: Option<N>,
    pub(crate) cell: Cell,
}

#[derive(Copy, Clone, Debug)]
struct AssignedInt<W: BaseExt, N: FieldExt> {
    pub(crate) value: Option<W>,
    pub(crate) limbs_le: [AssignedValue<N>; MAX_LIMBS],
    pub(crate) times: usize,
}

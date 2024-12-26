use halo2_proofs::arithmetic::{BaseExt, FieldExt};
use halo2_proofs::circuit::Cell;

pub struct AssignedValue<N: FieldExt> {
    pub(crate) value: Option<N>,
    pub(crate) cell: Cell,
}

struct AssignedInt<W: BaseExt, N: FieldExt, const LIMBS: usize> {
    pub(crate) value: Option<W>,
    pub(crate) limbs_le: [AssignedValue<N>; LIMBS],
    pub(crate) times: usize,
}

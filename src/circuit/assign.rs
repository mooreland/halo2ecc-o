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

pub enum MayAssignedValue<'a, N: FieldExt> {
    Assigned(&'a AssignedValue<N>),
    Unassigned(&'a N),
    UnassignedOwned(N),
}

impl<'a, N: FieldExt> MayAssignedValue<'a, N> {
    pub fn value(&self) -> Option<N> {
        match self {
            MayAssignedValue::Assigned(assigned) => assigned.value,
            MayAssignedValue::Unassigned(value) => Some(**value),
            MayAssignedValue::UnassignedOwned(value) => Some(*value),
        }
    }

    pub fn cell(&self) -> Option<Cell> {
        match self {
            MayAssignedValue::Assigned(assigned) => Some(assigned.cell),
            MayAssignedValue::Unassigned(_) => None,
            MayAssignedValue::UnassignedOwned(_) => None,
        }
    }
}

impl<'a, N: FieldExt> From<&'a AssignedValue<N>> for MayAssignedValue<'a, N> {
    fn from(assigned: &'a AssignedValue<N>) -> Self {
        MayAssignedValue::Assigned(&assigned)
    }
}

impl<'a, N: FieldExt> From<&'a N> for MayAssignedValue<'a, N> {
    fn from(value: &'a N) -> Self {
        MayAssignedValue::Unassigned(value)
    }
}

impl<'a, N: FieldExt> From<&'a Option<N>> for MayAssignedValue<'a, N> {
    fn from(value: &'a Option<N>) -> Self {
        match value {
            Some(value) => MayAssignedValue::Unassigned(value),
            None => MayAssignedValue::UnassignedOwned(N::zero()),
        }
    }
}

impl<'a, N: FieldExt> From<Option<N>> for MayAssignedValue<'a, N> {
    fn from(value: Option<N>) -> Self {
        match value {
            Some(value) => MayAssignedValue::UnassignedOwned(value),
            None => MayAssignedValue::UnassignedOwned(N::zero()),
        }
    }
}
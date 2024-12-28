use halo2_proofs::arithmetic::{BaseExt, FieldExt};
use halo2_proofs::circuit::Cell;

const MAX_LIMBS: usize = 3;

#[derive(Copy, Clone, Debug)]
pub struct AssignedValue<N: FieldExt> {
    pub(crate) value: Option<N>,
    pub(crate) cell: Cell,
}

impl<N: FieldExt> AssignedValue<N> {
    pub fn value(&self) -> Option<N> {
        self.value
    }

    pub fn cell(&self) -> Cell {
        self.cell
    }
}

#[derive(Copy, Clone, Debug)]
pub struct AssignedCondition<N: FieldExt> {
    pub(crate) value: Option<N>,
    pub(crate) cell: Cell,
}

impl<N: FieldExt> AssignedCondition<N> {
    pub fn value(&self) -> Option<N> {
        self.value
    }

    pub fn cell(&self) -> Cell {
        self.cell
    }
}

impl<'a, N: FieldExt> From<AssignedCondition<N>> for AssignedValue<N> {
    fn from(v: AssignedCondition<N>) -> Self {
        Self {
            value: v.value,
            cell: v.cell,
        }
    }
}

impl<'a, N: FieldExt> From<AssignedValue<N>> for AssignedCondition<N> {
    fn from(v: AssignedValue<N>) -> Self {
        Self {
            value: v.value,
            cell: v.cell,
        }
    }
}

impl<N: FieldExt> AsRef<AssignedValue<N>> for AssignedCondition<N> {
    fn as_ref(&self) -> &AssignedValue<N> {
        unsafe { std::mem::transmute(self) }
    }
}

#[derive(Copy, Clone, Debug)]
struct AssignedInt<W: BaseExt, N: FieldExt> {
    pub(crate) value: Option<W>,
    pub(crate) limbs_le: [AssignedValue<N>; MAX_LIMBS],
    pub(crate) times: usize,
}

pub trait MayAssignedValue<N: FieldExt> {
    fn value(&self) -> Option<N>;
    fn cell(&self) -> Option<Cell>;
}

impl<N: FieldExt> MayAssignedValue<N> for AssignedValue<N> {
    fn value(&self) -> Option<N> {
        self.value
    }

    fn cell(&self) -> Option<Cell> {
        Some(self.cell)
    }
}

impl<'a, N: FieldExt> MayAssignedValue<N> for &'a AssignedValue<N> {
    fn value(&self) -> Option<N> {
        self.value
    }

    fn cell(&self) -> Option<Cell> {
        Some(self.cell)
    }
}

impl<N: FieldExt> MayAssignedValue<N> for N {
    fn value(&self) -> Option<N> {
        Some(*self)
    }

    fn cell(&self) -> Option<Cell> {
        None
    }
}

impl<'a, N: FieldExt> MayAssignedValue<N> for &'a N {
    fn value(&self) -> Option<N> {
        Some(**self)
    }

    fn cell(&self) -> Option<Cell> {
        None
    }
}

impl<'a, N: FieldExt> MayAssignedValue<N> for &'a Option<N> {
    fn value(&self) -> Option<N> {
        match self {
            Some(value) => Some(*value),
            None => None,
        }
    }

    fn cell(&self) -> Option<Cell> {
        None
    }
}

impl<N: FieldExt> MayAssignedValue<N> for Option<N> {
    fn value(&self) -> Option<N> {
        self.clone()
    }

    fn cell(&self) -> Option<Cell> {
        None
    }
}

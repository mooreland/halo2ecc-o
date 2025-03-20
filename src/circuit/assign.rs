use std::marker::PhantomData;

use halo2_proofs::arithmetic::{BaseExt, CurveAffine, FieldExt};
use halo2_proofs::circuit::Cell;
use num_bigint::BigUint;

pub const MAX_LIMBS: usize = 3;

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

impl<N: FieldExt> From<AssignedCondition<N>> for AssignedValue<N> {
    fn from(v: AssignedCondition<N>) -> Self {
        Self {
            value: v.value,
            cell: v.cell,
        }
    }
}

impl<N: FieldExt> From<AssignedValue<N>> for AssignedCondition<N> {
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

#[derive(Clone, Debug)]
pub struct AssignedInteger<W: BaseExt, N: FieldExt> {
    pub(crate) value: Option<BigUint>,
    pub(crate) limbs_le: [Option<AssignedValue<N>>; MAX_LIMBS],
    pub(crate) native: AssignedValue<N>,
    pub(crate) times: usize,
    phantom: PhantomData<W>,
}

impl<W: BaseExt, N: FieldExt> AssignedInteger<W, N> {
    pub fn new(
        limbs_le: [Option<AssignedValue<N>>; MAX_LIMBS],
        native: AssignedValue<N>,
        value: Option<BigUint>,
    ) -> Self {
        Self {
            value,
            native,
            limbs_le,
            times: 1,
            phantom: PhantomData,
        }
    }

    pub fn new_with_times(
        limbs_le: [Option<AssignedValue<N>>; MAX_LIMBS],
        native: AssignedValue<N>,
        value: Option<BigUint>,
        times: usize,
    ) -> Self {
        Self {
            value,
            native,
            limbs_le,
            times,
            phantom: PhantomData,
        }
    }

    pub fn limbs(&self) -> &[Option<AssignedValue<N>>] {
        &self.limbs_le
    }
}

#[derive(Clone, Debug)]
pub struct AssignedPoint<C: CurveAffine, N: FieldExt> {
    pub x: AssignedInteger<C::Base, N>,
    pub y: AssignedInteger<C::Base, N>,
    pub z: AssignedCondition<N>,
}

impl<C: CurveAffine, N: FieldExt> AssignedPoint<C, N> {
    pub fn new(
        x: AssignedInteger<C::Base, N>,
        y: AssignedInteger<C::Base, N>,
        z: AssignedCondition<N>,
    ) -> Self {
        Self { x, y, z }
    }
}

#[derive(Clone, Debug)]
pub struct AssignedNonZeroPoint<C: CurveAffine, N: FieldExt> {
    pub x: AssignedInteger<C::Base, N>,
    pub y: AssignedInteger<C::Base, N>,
}

impl<C: CurveAffine, N: FieldExt> AssignedNonZeroPoint<C, N> {
    pub fn new(x: AssignedInteger<C::Base, N>, y: AssignedInteger<C::Base, N>) -> Self {
        Self { x, y }
    }
}

#[derive(Clone, Debug)]
pub struct AssignedCurvature<C: CurveAffine, N: FieldExt>(
    pub AssignedInteger<C::Base, N>,
    pub AssignedCondition<N>,
);

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

pub type AssignedFq<W, N> = AssignedInteger<W, N>;
pub type AssignedFq2<W, N> = (AssignedFq<W, N>, AssignedFq<W, N>);
pub type AssignedFq6<W, N> = (AssignedFq2<W, N>, AssignedFq2<W, N>, AssignedFq2<W, N>);
pub type AssignedFq12<W, N> = (AssignedFq6<W, N>, AssignedFq6<W, N>);

pub type AssignedG1Affine<C, N> = AssignedPoint<C, N>;

#[derive(Debug, Clone)]
pub struct AssignedG2Affine<C: CurveAffine, N: FieldExt> {
    pub x: AssignedFq2<C::Base, N>,
    pub y: AssignedFq2<C::Base, N>,
    pub z: AssignedCondition<N>,
    _mark: PhantomData<C>,
}

impl<C: CurveAffine, N: FieldExt> AssignedG2Affine<C, N> {
    pub fn new(
        x: AssignedFq2<C::Base, N>,
        y: AssignedFq2<C::Base, N>,
        z: AssignedCondition<N>,
    ) -> Self {
        Self {
            x,
            y,
            z,
            _mark: PhantomData,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AssignedG2<C: CurveAffine, N: FieldExt> {
    pub x: AssignedFq2<C::Base, N>,
    pub y: AssignedFq2<C::Base, N>,
    pub z: AssignedFq2<C::Base, N>,
    _mark: PhantomData<C>,
}

impl<C: CurveAffine, N: FieldExt> AssignedG2<C, N> {
    pub fn new(
        x: AssignedFq2<C::Base, N>,
        y: AssignedFq2<C::Base, N>,
        z: AssignedFq2<C::Base, N>,
    ) -> Self {
        Self {
            x,
            y,
            z,
            _mark: PhantomData,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AssignedG2Prepared<C: CurveAffine, N: FieldExt> {
    pub coeffs: Vec<[AssignedFq2<C::Base, N>; 3]>,
    // pub is_identity: AssignedCondition<N>, not support identity
    _mark: PhantomData<C>,
}

impl<C: CurveAffine, N: FieldExt> AssignedG2Prepared<C, N> {
    pub fn new(coeffs: Vec<[AssignedFq2<C::Base, N>; 3]>) -> Self {
        Self {
            coeffs,
            _mark: PhantomData,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AssignedG2OnProvePrepared<C: CurveAffine, N: FieldExt> {
    pub coeffs: Vec<[AssignedFq2<C::Base, N>; 2]>,
    pub init_q: AssignedG2Affine<C, N>,
    // pub is_identity: AssignedCondition<N>, not support identity
    _mark: PhantomData<C>,
}

impl<C: CurveAffine, N: FieldExt> AssignedG2OnProvePrepared<C, N> {
    pub fn new(coeffs: Vec<[AssignedFq2<C::Base, N>; 2]>, init_q: AssignedG2Affine<C, N>) -> Self {
        Self {
            coeffs,
            init_q,
            _mark: PhantomData,
        }
    }
}

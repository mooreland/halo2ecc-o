use std::ops::Sub;
use std::sync::Arc;

use halo2_proofs::arithmetic::{BaseExt, CurveAffine, FieldExt};
use halo2_proofs::circuit::Region;
use rayon::iter::{IntoParallelRefMutIterator as _, ParallelIterator as _};

use crate::range_info::RangeInfo;

use super::assign::{AssignedInteger, AssignedValue, MAX_LIMBS};
use super::int_mul_gate::IntMulGateConfig;
use super::kvmap_gate::KVMapGateConfig;
use super::plonk_gate::PlonkGateConfig;
use super::range_gate::RangeGateConfig;

#[derive(Clone, Copy, Debug)]
pub struct PlonkRegionContext<'a, N: FieldExt> {
    pub(crate) region: &'a Region<'a, N>,
    pub(crate) plonk_gate_config: &'a PlonkGateConfig,
    pub(crate) kvmap_gate_config: Option<&'a KVMapGateConfig>,
    pub offset: usize,
}

impl<'a, N: FieldExt> PlonkRegionContext<'a, N> {
    pub fn new(region: &'a Region<'a, N>, plonk_gate_config: &'a PlonkGateConfig) -> Self {
        Self {
            region,
            plonk_gate_config,
            kvmap_gate_config: None,
            offset: 0,
        }
    }

    pub fn new_with_kvmap(
        region: &'a Region<'a, N>,
        plonk_gate_config: &'a PlonkGateConfig,
        kvmap_gate_config: &'a KVMapGateConfig,
    ) -> Self {
        Self {
            region,
            plonk_gate_config,
            kvmap_gate_config: Some(kvmap_gate_config),
            offset: 0,
        }
    }

    pub fn set_offset(&mut self, offset: usize) {
        self.offset = offset;
    }
}

#[derive(Clone, Debug)]
pub struct IntegerContext<'a, W: BaseExt, N: FieldExt> {
    pub(crate) plonk_region_context: PlonkRegionContext<'a, N>,
    pub(crate) range_region_context: RangeRegionContext<'a, N>,
    pub(crate) int_mul_config: &'a IntMulGateConfig,
    pub(crate) info: Arc<RangeInfo<W, N>>,
    pub(crate) int_mul_queue: Vec<(
        AssignedInteger<W, N>,
        AssignedInteger<W, N>,
        [Option<AssignedValue<N>>; MAX_LIMBS],
        AssignedInteger<W, N>,
    )>,
}

impl<'a, W: BaseExt, N: FieldExt> IntegerContext<'a, W, N> {
    pub fn new(
        plonk_region_context: PlonkRegionContext<'a, N>,
        range_region_context: RangeRegionContext<'a, N>,
        int_mul_config: &'a IntMulGateConfig,
        info: Arc<RangeInfo<W, N>>,
    ) -> Self {
        Self {
            plonk_region_context,
            range_region_context,
            int_mul_config,
            info,
            int_mul_queue: vec![],
        }
    }
}

#[derive(Clone, Debug)]
pub struct NativeEccContext<'a, C: CurveAffine> {
    pub(crate) msm_index: u64,
    pub(crate) integer_context: IntegerContext<'a, C::Base, C::Scalar>,
}

impl<'a, C: CurveAffine> NativeEccContext<'a, C> {
    pub fn new(
        plonk_region_context: PlonkRegionContext<'a, C::Scalar>,
        range_region_context: RangeRegionContext<'a, C::Scalar>,
        int_mul_config: &'a IntMulGateConfig,
        info: Arc<RangeInfo<C::Base, C::Scalar>>,
    ) -> Self {
        Self {
            msm_index: 0,
            integer_context: IntegerContext::new(
                plonk_region_context,
                range_region_context,
                int_mul_config,
                info,
            ),
        }
    }

    pub fn get_plonk_region_context(&mut self) -> &mut PlonkRegionContext<'a, C::Scalar> {
        &mut self.integer_context.plonk_region_context
    }

    pub fn get_range_region_context(&mut self) -> &mut RangeRegionContext<'a, C::Scalar> {
        &mut self.integer_context.range_region_context
    }
}

impl<'a, W: BaseExt, N: FieldExt> Drop for IntegerContext<'a, W, N> {
    fn drop(&mut self) {
        assert!(self.int_mul_queue.is_empty())
    }
}

#[derive(Clone, Debug)]
pub struct RangeRegionContext<'a, N: FieldExt> {
    pub(crate) region: &'a Region<'a, N>,
    pub(crate) range_gate_config: &'a RangeGateConfig,
    pub(crate) compact_values: Vec<N>,
    pub(crate) compact_rows: Vec<usize>,
    pub(crate) free_common_cells: Vec<(usize, usize)>,
    pub offset: usize,
}

impl<'a, N: FieldExt> Drop for RangeRegionContext<'a, N> {
    fn drop(&mut self) {
        assert!(self.compact_values.is_empty());
        assert!(self.compact_rows.is_empty());
    }
}

impl<'a, N: FieldExt> RangeRegionContext<'a, N> {
    pub fn new(region: &'a Region<'a, N>, range_gate_config: &'a RangeGateConfig) -> Self {
        Self {
            region,
            range_gate_config,
            compact_values: Vec::new(),
            compact_rows: Vec::new(),
            free_common_cells: Vec::new(),
            offset: 0,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Offset {
    pub plonk_region_offset: usize,
    pub range_region_offset: usize,
}

impl Sub<Offset> for Offset {
    type Output = Offset;

    fn sub(mut self, rhs: Offset) -> Self::Output {
        self.plonk_region_offset -= rhs.plonk_region_offset;
        self.range_region_offset -= rhs.range_region_offset;
        return self;
    }
}

impl Offset {
    fn scale(&self, n: usize) -> Offset {
        Offset {
            plonk_region_offset: self.plonk_region_offset * n,
            range_region_offset: self.range_region_offset * n,
        }
    }

    fn less_or_equal(&self, rhs: &Offset) -> bool {
        self.plonk_region_offset <= rhs.plonk_region_offset
            && self.range_region_offset <= rhs.range_region_offset
    }
}

pub trait ParallelClone: Send + Sized {
    fn offset(&self) -> Offset;

    // WARNING: cloned object should be merged for finalization ops.
    fn clone_with_offset(&self, offset_diff: &Offset) -> Self;
    fn merge_mut(&mut self, other: &mut Self);

    fn merge(&mut self, mut other: Self) {
        self.merge_mut(&mut other);
    }

    fn clone_without_offset(&self) -> Self {
        self.clone_with_offset(&Offset {
            plonk_region_offset: 0,
            range_region_offset: 0,
        })
    }

    fn do_parallel<T: Send, E: Send, F: Sync + Fn(&mut Self, usize) -> Result<T, E>>(
        &mut self,
        f: F,
        len: usize,
    ) -> Result<Vec<T>, E> {
        if len == 0 {
            return Ok(vec![]);
        }

        let mut res = vec![];

        let offset_diff = {
            // MUST predict with cloned context.
            let mut predict_ops = self.clone_without_offset();
            let offset_before = predict_ops.offset();
            res.push(f(&mut predict_ops, 0)?);
            let offset_after = predict_ops.offset();
            self.merge(predict_ops);

            offset_after - offset_before
        };

        let mut cloned_ops = (1..len)
            .into_iter()
            .map(|i| (i, self.clone_with_offset(&offset_diff.scale(i - 1))))
            .collect::<Vec<_>>();

        let mut arr = cloned_ops
            .par_iter_mut()
            .map(|(wi, op)| -> Result<T, E> {
                let offset_before = op.offset();
                let v = f(op, *wi)?;
                let offset_after = op.offset();
                assert!((offset_after - offset_before).less_or_equal(&offset_diff));
                Ok(v)
            })
            .collect::<Result<Vec<_>, _>>()?;

        res.append(&mut arr);

        for (_, op) in cloned_ops {
            self.merge(op);
        }

        Ok(res)
    }
}

impl<'b, C: CurveAffine> ParallelClone for NativeEccContext<'b, C> {
    fn clone_with_offset(&self, offset_diff: &Offset) -> Self {
        NativeEccContext {
            msm_index: self.msm_index,
            integer_context: self.integer_context.clone_with_offset(offset_diff),
        }
    }

    fn offset(&self) -> Offset {
        self.integer_context.offset()
    }

    fn merge_mut(&mut self, other: &mut Self) {
        self.integer_context.merge_mut(&mut other.integer_context);
        self.msm_index = self.msm_index.max(other.msm_index);
    }
}

impl<'b, W: BaseExt, N: FieldExt> ParallelClone for IntegerContext<'b, W, N> {
    fn clone_with_offset(&self, offset_diff: &Offset) -> Self {
        IntegerContext {
            plonk_region_context: self.plonk_region_context.clone_with_offset(offset_diff),
            range_region_context: self.range_region_context.clone_with_offset(offset_diff),
            int_mul_config: self.int_mul_config,
            info: self.info.clone(),
            int_mul_queue: vec![],
        }
    }

    fn offset(&self) -> Offset {
        Offset {
            plonk_region_offset: self.plonk_region_context.offset,
            range_region_offset: self.range_region_context.offset,
        }
    }

    fn merge_mut(&mut self, other: &mut Self) {
        self.int_mul_queue.append(&mut other.int_mul_queue);
        self.plonk_region_context
            .merge_mut(&mut other.plonk_region_context);
        self.range_region_context
            .merge_mut(&mut other.range_region_context);
    }
}

impl<'b, N: FieldExt> ParallelClone for RangeRegionContext<'b, N> {
    fn clone_with_offset(&self, offset_diff: &Offset) -> Self {
        Self {
            region: self.region,
            range_gate_config: self.range_gate_config,
            compact_values: vec![],
            compact_rows: vec![],
            free_common_cells: vec![],
            offset: self.offset + offset_diff.range_region_offset,
        }
    }

    fn offset(&self) -> Offset {
        Offset {
            plonk_region_offset: 0,
            range_region_offset: self.offset,
        }
    }

    fn merge_mut(&mut self, other: &mut Self) {
        assert!(other.offset >= self.offset);
        self.offset = other.offset;

        self.compact_rows.append(&mut other.compact_rows);
        self.compact_values.append(&mut other.compact_values);
        self.free_common_cells.append(&mut other.free_common_cells);
    }
}

impl<'b, N: FieldExt> ParallelClone for PlonkRegionContext<'b, N> {
    fn clone_with_offset(&self, offset_diff: &Offset) -> Self {
        PlonkRegionContext {
            region: self.region,
            plonk_gate_config: self.plonk_gate_config,
            kvmap_gate_config: self.kvmap_gate_config,
            offset: self.offset + offset_diff.plonk_region_offset,
        }
    }

    fn offset(&self) -> Offset {
        Offset {
            plonk_region_offset: self.offset,
            range_region_offset: 0,
        }
    }

    fn merge_mut(&mut self, other: &mut Self) {
        assert!(other.offset >= self.offset);
        self.offset = other.offset;
    }
}

use std::sync::Arc;

use halo2_proofs::arithmetic::{BaseExt, FieldExt};
use halo2_proofs::circuit::Region;

use crate::range_info::RangeInfo;

use super::assign::{AssignedInteger, AssignedValue, MAX_LIMBS};
use super::int_mul_gate::IntMulGateConfig;
use super::plonk_gate::PlonkGateConfig;
use super::range_gate::RangeGateConfig;

#[derive(Clone, Copy, Debug)]
pub struct PlonkRegionContext<'a, N: FieldExt> {
    pub(crate) region: &'a Region<'a, N>,
    pub(crate) plonk_gate_config: &'a PlonkGateConfig,
    pub offset: usize,
}

impl<'a, N: FieldExt> PlonkRegionContext<'a, N> {
    pub fn new(region: &'a Region<'a, N>, plonk_gate_config: &'a PlonkGateConfig) -> Self {
        Self {
            region,
            plonk_gate_config,
            offset: 0,
        }
    }

    pub fn set_offset(&mut self, offset: usize) {
        self.offset = offset;
    }
}

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

impl<'a, W: BaseExt, N: FieldExt> Drop for IntegerContext<'a, W, N> {
    fn drop(&mut self) {
        assert!(self.int_mul_queue.is_empty())
    }
}

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

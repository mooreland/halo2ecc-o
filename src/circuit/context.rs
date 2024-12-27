use halo2_proofs::arithmetic::{BaseExt, FieldExt};
use halo2_proofs::circuit::{Cell, Region};

use super::plonk_gate::PlonkGateConfig;
use super::range_gate::RangeGateConfig;

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

pub struct RangeRegionContext<'a, N: FieldExt> {
    pub(crate) region: &'a Region<'a, N>,
    pub(crate) range_gate_config: &'a RangeGateConfig,
    pub(crate) compact_values: Vec<N>,
    pub(crate) compact_rows: Vec<usize>,
    pub(crate) free_common_cells: Vec<(usize, usize)>,
    pub offset: usize,
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

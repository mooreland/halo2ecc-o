pub mod assign;
pub mod chips;
pub mod context;
pub mod gates;

use context::{
    GeneralScalarEccContext, NativeScalarEccContext, PlonkRegionContext, RangeRegionContext,
};
use halo2_proofs::{
    arithmetic::CurveAffine, arithmetic::FieldExt, circuit::Region, plonk::ConstraintSystem,
};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

pub use gates::*;
use int_mul_gate::{IntMulGate, IntMulGateConfig};
use kvmap_gate::{KVMapGate, KVMapGateConfig};
use plonk_gate::{PlonkGate, PlonkGateConfig};
use range_gate::{RangeGate, RangeGateConfig};

use crate::range_info::RangeInfo;

#[derive(Debug, Clone)]
pub struct NativeScalarEccConfig {
    pub plonk_gate_config: PlonkGateConfig,
    pub range_gate_config: RangeGateConfig,
    pub int_mul_gate_config: IntMulGateConfig,
    pub kvmap_gate_config: KVMapGateConfig,
}

impl NativeScalarEccConfig {
    pub fn configure<C: CurveAffine>(meta: &mut ConstraintSystem<C::Scalar>) -> Self {
        let plonk_gate_config = PlonkGate::<C::Scalar>::configure(meta);
        let range_gate_config = RangeGate::configure(meta);
        let int_mul_gate_config = IntMulGate::configure(
            meta,
            plonk_gate_config.var,
            &RangeInfo::<C::Base, C::Scalar>::new(),
        );
        let kvmap_gate_config =
            KVMapGate::configure(meta, plonk_gate_config.var[0..2].try_into().unwrap());

        NativeScalarEccConfig {
            plonk_gate_config,
            range_gate_config,
            int_mul_gate_config,
            kvmap_gate_config,
        }
    }

    pub fn to_context<'a, C: CurveAffine>(
        &'a self,
        region: &'a Region<'_, C::Scalar>,
    ) -> NativeScalarEccContext<'a, C> {
        let plonk_region_context = PlonkRegionContext::new_with_kvmap(
            region,
            &self.plonk_gate_config,
            &self.kvmap_gate_config,
        );
        let range_region_context = RangeRegionContext::new(&region, &self.range_gate_config);

        NativeScalarEccContext::new(
            Rc::new(RefCell::new(plonk_region_context)),
            Rc::new(RefCell::new(range_region_context)),
            &self.int_mul_gate_config,
            RangeInfo::new(),
        )
    }
}

#[derive(Debug, Clone)]
pub struct GeneralScalarEccConfig {
    pub plonk_gate_config: PlonkGateConfig,
    pub range_gate_config: RangeGateConfig,
    pub int_mul_gate_config: IntMulGateConfig,
    pub kvmap_gate_config: KVMapGateConfig,
}

impl GeneralScalarEccConfig {
    pub fn configure<C: CurveAffine, N: FieldExt>(meta: &mut ConstraintSystem<N>) -> Self {
        let plonk_gate_config = PlonkGate::<N>::configure(meta);
        let range_gate_config = RangeGate::configure(meta);
        let int_mul_gate_config =
            IntMulGate::configure(meta, plonk_gate_config.var, &RangeInfo::<C::Base, N>::new());
        let kvmap_gate_config =
            KVMapGate::configure(meta, plonk_gate_config.var[0..2].try_into().unwrap());

        GeneralScalarEccConfig {
            plonk_gate_config,
            range_gate_config,
            int_mul_gate_config,
            kvmap_gate_config,
        }
    }

    pub fn to_context<'a, C: CurveAffine, N: FieldExt>(
        &'a self,
        region: &'a Region<'_, N>,
    ) -> GeneralScalarEccContext<'a, C, N> {
        let plonk_region_context = PlonkRegionContext::new_with_kvmap(
            region,
            &self.plonk_gate_config,
            &self.kvmap_gate_config,
        );

        let range_region_context = RangeRegionContext::new(&region, &self.range_gate_config);

        GeneralScalarEccContext::new(
            Rc::new(RefCell::new(plonk_region_context)),
            Rc::new(RefCell::new(range_region_context)),
            &self.int_mul_gate_config,
            RangeInfo::<C::Base, N>::new(),
            RangeInfo::<C::Scalar, N>::new(),
        )
    }
}

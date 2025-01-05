use std::marker::PhantomData;

use halo2_proofs::plonk::{Error, Expression};
use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{Advice, Column, ConstraintSystem, Fixed},
    poly::Rotation,
};

use crate::assign::AssignedValue;
use crate::context::PlonkRegionContext;

#[derive(Clone, Debug)]
pub struct KVMapGateConfig {
    pub gid: Column<Fixed>,
    pub key: Column<Advice>,
    pub value: Column<Advice>,
    pub is_get: Column<Fixed>,
}

pub struct KVMapGate<N: FieldExt> {
    pub config: KVMapGateConfig,
    pub _phantom: PhantomData<N>,
}

impl<N: FieldExt> KVMapGate<N> {
    pub fn new(config: KVMapGateConfig) -> Self {
        KVMapGate {
            config,
            _phantom: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<N>, cols: [Column<Advice>; 2]) -> KVMapGateConfig {
        let [key, value] = cols;
        let gid = meta.fixed_column();
        let is_get = meta.fixed_column();

        meta.enable_equality(key);
        meta.enable_equality(value);

        meta.lookup_any("kvmap lookup", |meta| {
            let key = meta.query_advice(key, Rotation::cur());
            let value = meta.query_advice(value, Rotation::cur());
            let gid = meta.query_fixed(gid, Rotation::cur());
            let is_get = meta.query_fixed(is_get, Rotation::cur());

            vec![
                (gid.clone(), gid),
                (key.clone(), key),
                (value.clone(), value),
                (Expression::Constant(N::zero()), is_get),
            ]
        });

        KVMapGateConfig {
            gid,
            key,
            value,
            is_get,
        }
    }
}

// A range info that implements limb assignment for W on N
pub trait KVMapOps<N: FieldExt> {
    fn kvmap_set(
        &mut self,
        gid: u64,
        k: &AssignedValue<N>,
        v: &AssignedValue<N>,
    ) -> Result<(), Error>;
    fn kvmap_get(
        &mut self,
        gid: u64,
        k: &AssignedValue<N>,
        v: Option<N>,
    ) -> Result<AssignedValue<N>, Error>;
}

impl<'a, N: FieldExt> KVMapOps<N> for PlonkRegionContext<'a, N> {
    fn kvmap_set(
        &mut self,
        gid: u64,
        k: &AssignedValue<N>,
        v: &AssignedValue<N>,
    ) -> Result<(), Error> {
        let k_cell = self.region.assign_advice(
            || "",
            self.kvmap_gate_config.unwrap().key,
            self.offset,
            || Ok(k.value().unwrap()),
        )?;
        self.region.constrain_equal(k_cell.cell(), k.cell())?;

        let v_cell = self.region.assign_advice(
            || "",
            self.kvmap_gate_config.unwrap().value,
            self.offset,
            || Ok(v.value().unwrap()),
        )?;
        self.region.constrain_equal(v_cell.cell(), v.cell())?;

        self.region.assign_fixed(
            || "",
            self.kvmap_gate_config.unwrap().gid,
            self.offset,
            || Ok(N::from(gid)),
        )?;

        // Skip - assign zero
        if false {
            self.region.assign_fixed(
                || "",
                self.kvmap_gate_config.unwrap().is_get,
                self.offset,
                || Ok(N::zero()),
            )?;
        }

        self.offset += 1;

        Ok(())
    }

    fn kvmap_get(
        &mut self,
        gid: u64,
        k: &AssignedValue<N>,
        v: Option<N>,
    ) -> Result<AssignedValue<N>, Error> {
        let k_cell = self.region.assign_advice(
            || "",
            self.kvmap_gate_config.unwrap().key,
            self.offset,
            || Ok(k.value().unwrap()),
        )?;
        self.region.constrain_equal(k_cell.cell(), k.cell())?;

        let v_cell = self.region.assign_advice(
            || "",
            self.kvmap_gate_config.unwrap().value,
            self.offset,
            || Ok(v.unwrap()),
        )?;

        self.region.assign_fixed(
            || "",
            self.kvmap_gate_config.unwrap().gid,
            self.offset,
            || Ok(N::from(gid)),
        )?;

        self.region.assign_fixed(
            || "",
            self.kvmap_gate_config.unwrap().is_get,
            self.offset,
            || Ok(N::one()),
        )?;

        self.offset += 1;

        Ok(AssignedValue {
            value: v,
            cell: v_cell.cell(),
        })
    }
}

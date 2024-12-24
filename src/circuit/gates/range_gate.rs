use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::Advice;
use halo2_proofs::plonk::Column;
use halo2_proofs::plonk::ConstraintSystem;
use halo2_proofs::plonk::Expression;
use halo2_proofs::plonk::Fixed;
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
use std::vec;

use crate::range_info::*;

const BITS: usize = COMMON_RANGE_BITS as usize; // value is 18
const ADV_COLUMNS: usize = RANGE_VALUE_DECOMPOSE as usize; // value is 6
const COMPACT_CELLS: usize = RANGE_VALUE_DECOMPOSE as usize; // value is 6

// const COMPACT_BITS: usize = BITS * COMPACT_CELLS; // value is 108

#[derive(Clone, Debug)]
pub struct RangeGateConfig {
    // All cells are limited to 2^BITS by lookup table.
    pub var_cols: [Column<Advice>; ADV_COLUMNS],

    // The sum_limit is used for small range check,
    // with gates `sum_limit[row] = var_cols[0][row] + var_cols[1][row] + 1`.
    // Suppose we want a cell in which the value < R, and R < 2 ** BITS.
    // We alloc a row and assign sum_limit[row] = R.
    // Because var_cols[0][row] < 2^BITS, var_cols[1][row] < 2^BITS,
    // the two cells must be less than R.
    pub sum_limit: Column<Fixed>,
    pub sum_limit_sel: Column<Fixed>,

    // Used to compact COMPACT_CELLS(6) cells into COMPACT_BITS(108) in BE.
    pub acc: Column<Advice>,
    pub acc_sel: Column<Fixed>,

    // u18 table
    pub ubits_table: Column<Fixed>,
}

pub struct RangeGate<N: FieldExt> {
    pub config: RangeGateConfig,
    pub _phantom: PhantomData<N>,
}

impl<N: FieldExt> RangeGate<N> {
    pub fn new(config: RangeGateConfig) -> Self {
        RangeGate {
            config,
            _phantom: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<N>) -> RangeGateConfig {
        let var_cols = [0; ADV_COLUMNS].map(|_| meta.advice_column());
        let sum_limit = meta.fixed_column();
        let sum_limit_sel = meta.fixed_column();
        let acc = meta.advice_column();
        let acc_sel = meta.fixed_column();
        let ubits_table = meta.fixed_column();

        for i in 0..ADV_COLUMNS {
            meta.enable_equality(var_cols[i]);
            meta.lookup_any("range gate lookup", |meta| {
                vec![(
                    meta.query_advice(var_cols[i], Rotation::cur()),
                    meta.query_fixed(ubits_table, Rotation::cur()),
                )]
            });
        }

        meta.create_gate("range gate acc", |meta| {
            let sel = meta.query_fixed(acc_sel, Rotation::cur());
            let acc = meta.query_advice(acc, Rotation::cur());

            assert!(ADV_COLUMNS >= COMPACT_CELLS);
            let shift = Expression::Constant(N::from(1u64 << BITS));
            let mut acc_value = meta.query_advice(var_cols[0], Rotation::cur());
            for i in 1..COMPACT_CELLS {
                acc_value =
                    acc_value * shift.clone() + meta.query_advice(var_cols[i], Rotation::cur());
            }

            vec![sel * (acc - acc_value)]
        });

        meta.create_gate("range gate sum_limit", |meta| {
            let sel = meta.query_fixed(sum_limit_sel, Rotation::cur());
            let sum = meta.query_advice(var_cols[0], Rotation::cur())
                + meta.query_advice(var_cols[1], Rotation::cur())
                - meta.query_fixed(sum_limit, Rotation::cur())
                - Expression::Constant(N::one());
            vec![sel * sum]
        });

        RangeGateConfig {
            var_cols,
            sum_limit,
            sum_limit_sel,
            acc,
            acc_sel,
            ubits_table,
        }
    }
}

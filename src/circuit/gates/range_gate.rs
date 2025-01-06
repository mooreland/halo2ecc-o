use ark_std::Zero;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::Advice;
use halo2_proofs::plonk::Column;
use halo2_proofs::plonk::ConstraintSystem;
use halo2_proofs::plonk::Error;
use halo2_proofs::plonk::Expression;
use halo2_proofs::plonk::Fixed;
use halo2_proofs::poly::Rotation;
use num_bigint::BigUint;
use std::marker::PhantomData;
use std::vec;

use crate::assign::AssignedValue;
use crate::context::RangeRegionContext;
use crate::range_info::*;
use crate::util::*;

const BITS: usize = COMMON_RANGE_BITS as usize; // value is 18
const ADV_COLUMNS: usize = 3;

pub(crate) const COMPACT_CELLS: usize = RANGE_VALUE_DECOMPOSE as usize; // value is 6
pub(crate) const COMPACT_BITS: usize = BITS * COMPACT_CELLS; // value is 108

#[derive(Clone, Debug)]
pub struct RangeGateConfig {
    // All cells are limited to 2^BITS by lookup table.
    pub var_cols: [Column<Advice>; ADV_COLUMNS],

    // The sum_limit is used for small range check,
    // with gates `sum_limit[row] = var_cols[0][row] + var_cols[1][row]`.
    // Suppose we want a cell in which the value <= R, and R < 2 ** BITS.
    // We alloc a row and assign sum_limit[row] = R.
    // Because var_cols[0][row] < 2^BITS, var_cols[1][row] < 2^BITS,
    // the two cells must be less than or equal to R.
    pub sum_limit: Column<Fixed>,
    pub sum_limit_sel: Column<Fixed>,

    // Used to compact COMPACT_CELLS(6) cells into COMPACT_BITS(108) in BE.
    pub compact: Column<Advice>,
    pub compact_sel: Column<Fixed>,

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
        let compact = meta.advice_column();
        let compact_sel = meta.fixed_column();
        let ubits_table = meta.fixed_column();

        meta.enable_equality(compact);

        for i in 0..ADV_COLUMNS {
            meta.enable_equality(var_cols[i]);
            meta.lookup_any("range gate lookup", |meta| {
                vec![(
                    meta.query_advice(var_cols[i], Rotation::cur()),
                    meta.query_fixed(ubits_table, Rotation::cur()),
                )]
            });
        }

        meta.create_gate("range gate compact", |meta| {
            let sel = meta.query_fixed(compact_sel, Rotation::cur());
            let compact = meta.query_advice(compact, Rotation::cur());

            let mut compact_value = compact;
            for i in 0..COMPACT_CELLS {
                compact_value = compact_value
                    - meta.query_advice(
                        var_cols[i % ADV_COLUMNS],
                        Rotation((i / ADV_COLUMNS) as i32),
                    ) * Expression::Constant((BigUint::from(1u64) << (i * BITS)).to_field());
            }

            vec![sel * compact_value]
        });

        meta.create_gate("range gate sum_limit", |meta| {
            let sel = meta.query_fixed(sum_limit_sel, Rotation::cur());
            let sum = meta.query_advice(var_cols[0], Rotation::cur())
                + meta.query_advice(var_cols[1], Rotation::cur())
                - meta.query_fixed(sum_limit, Rotation::cur());
            vec![sel * sum]
        });

        RangeGateConfig {
            var_cols,
            sum_limit,
            sum_limit_sel,
            compact,
            compact_sel,
            ubits_table,
        }
    }
}

impl<'a, N: FieldExt> RangeRegionContext<'a, N> {
    pub fn init(&self) -> Result<(), Error> {
        for i in 0..1 << BITS {
            self.region.assign_fixed(
                || "init",
                self.range_gate_config.ubits_table,
                i as usize,
                || Ok(N::from(i)),
            )?;
        }
        Ok(())
    }

    pub fn assign_common_range_cell(
        &mut self,
        value: Option<N>,
    ) -> Result<AssignedValue<N>, Error> {
        let (row, col) = if let Some((free_row, col)) = self.free_common_cells.pop() {
            if col + 1 < ADV_COLUMNS {
                self.free_common_cells.push((free_row, col + 1));
            }
            (free_row, col)
        } else {
            let row = self.offset;
            self.free_common_cells.push((row, 1));
            self.offset += 1;
            (row, 0)
        };

        let assigned = self.region.assign_advice(
            || "assign_common_range_cell",
            self.range_gate_config.var_cols[col],
            row,
            || Ok(value.unwrap()),
        )?;
        Ok(AssignedValue {
            value,
            cell: assigned.cell(),
        })
    }

    // value <= range
    pub fn assign_custom_range_cell(
        &mut self,
        value: Option<N>,
        range: N,
    ) -> Result<AssignedValue<N>, Error> {
        self.region.assign_fixed(
            || "assign_range_cell",
            self.range_gate_config.sum_limit_sel,
            self.offset,
            || Ok(N::one()),
        )?;
        self.region.assign_fixed(
            || "assign_range_cell",
            self.range_gate_config.sum_limit,
            self.offset,
            || Ok(range),
        )?;

        self.region.assign_advice(
            || "assign_range_cell",
            self.range_gate_config.var_cols[1],
            self.offset,
            || Ok(range - value.unwrap()),
        )?;
        let assigned = self.region.assign_advice(
            || "assign_range_cell",
            self.range_gate_config.var_cols[0],
            self.offset,
            || Ok(value.unwrap()),
        )?;

        if 2 < ADV_COLUMNS {
            self.free_common_cells.push((self.offset, 2));
        }

        self.offset += 1;

        Ok(AssignedValue {
            value,
            cell: assigned.cell(),
        })
    }

    pub fn assign_compact_cell(&mut self, value: Option<N>) -> Result<AssignedValue<N>, Error> {
        self.region.assign_fixed(
            || "assign_compact_cell",
            self.range_gate_config.compact_sel,
            self.offset,
            || Ok(N::one()),
        )?;
        let assigned = self.region.assign_advice(
            || "assign_compact_cell",
            self.range_gate_config.compact,
            self.offset,
            || Ok(value.unwrap()),
        )?;

        // Skip on non-advices-assignment stage
        if assigned.value().is_some() {
            self.compact_values.push(value.unwrap_or(N::zero()));
            self.compact_rows.push(self.offset);
        }

        self.offset += (COMPACT_CELLS + ADV_COLUMNS - 1) / ADV_COLUMNS;

        Ok(AssignedValue {
            value,
            cell: assigned.cell(),
        })
    }

    pub fn finalize_compact_cells(&mut self) -> Result<(), Error> {
        for (offset, value) in self.compact_rows.iter().zip(self.compact_values.iter()) {
            // TOOPTIMIZED: use GPU to batch all operations.
            let mut value_bn = field_to_bn(value);
            for i in 0..COMPACT_CELLS {
                self.region.assign_advice(
                    || "assign_compact_cell",
                    self.range_gate_config.var_cols[i % ADV_COLUMNS],
                    *offset + i / ADV_COLUMNS,
                    || {
                        let v = (&value_bn & BigUint::from((1u64 << BITS) - 1)).to_field();
                        value_bn >>= BITS as u32;
                        Ok(v)
                    },
                )?;
            }
            assert!(value_bn.is_zero());
        }
        self.compact_values.clear();
        self.compact_rows.clear();
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::range_gate::RangeGate;
    use crate::util::test::*;
    use ark_std::{end_timer, start_timer};
    use floor_planner::V1;
    use halo2_proofs::circuit::*;
    use halo2_proofs::pairing::bn256::Fr;
    use halo2_proofs::plonk::*;

    #[derive(Clone, Debug)]
    struct RangeTestCircuit {
        common_start: u64,
        range_value: u64,
        range_limit: u64,
    }

    impl Circuit<Fr> for RangeTestCircuit {
        type Config = RangeGateConfig;
        type FloorPlanner = V1;

        fn configure(meta: &mut ConstraintSystem<Fr>) -> RangeGateConfig {
            RangeGate::<Fr>::configure(meta)
        }

        fn without_witnesses(&self) -> Self {
            self.clone()
        }

        fn synthesize(
            &self,
            config: Self::Config,
            layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let timer = start_timer!(|| "synthesize");
            layouter.assign_region(
                || "range_gate",
                |region| {
                    let mut context = RangeRegionContext::new(region, &config);

                    context.init()?;

                    let mut v = Fr::zero();
                    for _ in 0..(1 << 19) - 30 {
                        context.assign_compact_cell(Some(v))?;
                        v += Fr::one();
                    }

                    let timer = start_timer!(|| "finalize_compact_cells");
                    context.finalize_compact_cells()?;
                    end_timer!(timer);

                    context.assign_custom_range_cell(
                        Some(Fr::from(self.range_value)),
                        Fr::from(self.range_limit),
                    )?;
                    for i in 0..30 {
                        context.assign_common_range_cell(Some(Fr::from(
                            self.common_start + i as u64,
                        )))?;
                    }

                    Ok(())
                },
            )?;
            end_timer!(timer);
            Ok(())
        }
    }

    #[test]
    #[cfg(feature = "profile")]
    fn bench_range_gate() {
        bench_circuit_on_bn256(
            RangeTestCircuit {
                common_start: 0,
                range_value: 10,
                range_limit: 16,
            },
            20,
        );
    }

    #[test]
    fn test_range_gate_success() {
        run_circuit_on_bn256(
            RangeTestCircuit {
                common_start: 0,
                range_value: 10,
                range_limit: 16,
            },
            20,
        );
    }

    #[test]
    fn test_range_gate_fail() {
        run_circuit_on_bn256_expect_fail(
            RangeTestCircuit {
                common_start: 1 << BITS,
                range_value: 10,
                range_limit: 16,
            },
            20,
        );
        run_circuit_on_bn256_expect_fail(
            RangeTestCircuit {
                common_start: (1 << BITS) + 1,
                range_value: 10,
                range_limit: 16,
            },
            20,
        );
        run_circuit_on_bn256_expect_fail(
            RangeTestCircuit {
                common_start: 0,
                range_value: 17,
                range_limit: 16,
            },
            20,
        );
        run_circuit_on_bn256_expect_fail(
            RangeTestCircuit {
                common_start: 0,
                range_value: 1 << BITS,
                range_limit: 1 << BITS,
            },
            20,
        );
    }
}

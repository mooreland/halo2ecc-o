use crate::assign::{AssignedInteger, AssignedValue};
use crate::context::IntegerContext;
use crate::range_info::{get_bn_compact_range_to_field, RangeInfo};
use crate::utils::field_to_bn;
use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::plonk::{Error, Expression, VirtualCells};
use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{Advice, Column, ConstraintSystem, Fixed},
    poly::Rotation,
};
use std::marker::PhantomData;

use super::plonk_gate::VAR_COLUMNS;

#[derive(Clone, Debug)]
pub struct IntMulGateConfig {
    pub vars: [Column<Advice>; VAR_COLUMNS],
    pub sel: Column<Fixed>,
    pub block_rows: usize,

    pub a: Vec<(usize, i32)>,
    pub b: Vec<(usize, i32)>,
    pub d: Vec<(usize, i32)>,
    pub rem: Vec<(usize, i32)>,
    pub v_list: Vec<((usize, i32), (usize, i32))>,
}

#[derive(Clone, Debug)]
pub struct IntMulGate<W: BaseExt, N: FieldExt> {
    pub config: IntMulGateConfig,
    mark: PhantomData<(W, N)>,
}

impl<W: BaseExt, N: FieldExt> IntMulGate<W, N> {
    pub fn new(config: IntMulGateConfig) -> Self {
        Self {
            config,
            mark: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<N>,
        vars: [Column<Advice>; VAR_COLUMNS],
        info: &RangeInfo<W, N>,
    ) -> IntMulGateConfig {
        let sel = meta.fixed_column();

        // constraints_for_mul_equation_on_limbs in gates mod
        /*
         * inputs: a limbs, b limbs, d, rem limbs
         * l0 = a0 * b0 - d0 * w0
         * l1 = a1 * b0 + a0 * b1 - d1 * w0 - d0 * w1
         * ...
         */

        let mut col_rot = 0;
        let mut row_rot = 0;
        let mut alloc = || {
            let col = col_rot;
            let row = row_rot;
            col_rot += 1;
            if col_rot == VAR_COLUMNS {
                col_rot = 0;
                row_rot += 1;
            }
            (col, row)
        };

        let a = (0..info.limbs)
            .into_iter()
            .map(|_| alloc())
            .collect::<Vec<_>>();

        let b = (0..info.limbs)
            .into_iter()
            .map(|_| alloc())
            .collect::<Vec<_>>();

        let d = (0..info.limbs)
            .into_iter()
            .map(|_| alloc())
            .collect::<Vec<_>>();

        let rem = (0..info.limbs)
            .into_iter()
            .map(|_| alloc())
            .collect::<Vec<_>>();

        let v_list: Vec<_> = (0..info.mul_check_limbs)
            .map(|_| (alloc(), alloc()))
            .collect();

        let to_cell =
            |meta: &mut VirtualCells<N>, (col, row)| meta.query_advice(vars[col], Rotation(row));

        let to_constant = |n| Expression::Constant(n);

        meta.create_gate("int_mul_gate", |meta| {
            let mut constraints = vec![];

            let mut limbs_sum = vec![];
            for pos in 0..info.mul_check_limbs as usize {
                let r_bound = usize::min(pos + 1, info.limbs as usize);
                let l_bound = pos.checked_sub(info.limbs as usize - 1).unwrap_or(0);
                //println!("pos {}, l_bound {}, r_bound {}, info.limbs {}", pos, l_bound, r_bound, info.limbs);
                let sum = (l_bound..r_bound)
                    .map(|i| {
                        to_cell(meta, a[i]) * to_cell(meta, b[pos - i])
                            - to_cell(meta, d[i]) * to_constant(info.w_modulus_limbs_le[pos - i])
                    })
                    .reduce(|acc, x| acc + x)
                    .unwrap();

                limbs_sum.push(sum);
            }

            let mut v_h = v_list[0].0;
            let mut v_l = v_list[0].1;
            let borrow = N::from(info.limbs) * info.limb_modulus_n + N::from(2u64);
            {
                let u = limbs_sum[0].clone() - to_cell(meta, rem[0])
                    + to_constant(borrow * info.limb_modulus_n);

                // prove (limbs[0] + borrow - rem[0]) % limbs_size == 0
                constraints.push(
                    to_cell(meta, v_h) * to_constant(info.limb_coeffs[2])
                        + to_cell(meta, v_l) * to_constant(info.limb_coeffs[1])
                        - u,
                );
            }

            let borrow = borrow * info.limb_modulus_n - borrow;
            for i in 1..info.limbs as usize {
                let u = limbs_sum[i].clone() - to_cell(meta, rem[i])
                    + to_cell(meta, v_h) * to_constant(info.limb_coeffs[1])
                    + to_cell(meta, v_l) * to_constant(info.limb_coeffs[0])
                    + to_constant(borrow);
                v_h = v_list[i].0;
                v_l = v_list[i].1;

                // prove (limbs[0] + borrow - rem[0]) % limbs_size == 0
                constraints.push(
                    to_cell(meta, v_h) * to_constant(info.limb_coeffs[2])
                        + to_cell(meta, v_l) * to_constant(info.limb_coeffs[1])
                        - u,
                );
            }

            // Only required by bl12_381 base field
            for i in info.limbs as usize..info.mul_check_limbs as usize {
                let u = limbs_sum[i].clone()
                    + to_cell(meta, v_h) * to_constant(info.limb_coeffs[1])
                    + to_cell(meta, v_l) * to_constant(info.limb_coeffs[0])
                    + to_constant(borrow);
                v_h = v_list[i].0;
                v_l = v_list[i].1;

                // prove (limbs[0] + borrow - rem[0]) % limbs_size == 0
                constraints.push(
                    to_cell(meta, v_h) * to_constant(info.limb_coeffs[2])
                        + to_cell(meta, v_l) * to_constant(info.limb_coeffs[1])
                        - u,
                );
            }

            constraints
                .into_iter()
                .map(|x| x * meta.query_fixed(sel, Rotation::cur()))
                .collect::<Vec<_>>()
        });

        IntMulGateConfig {
            vars,
            sel,
            block_rows: row_rot as usize + 1,
            a,
            b,
            d,
            rem,
            v_list,
        }
    }
}

impl<'a, W: BaseExt, N: FieldExt> IntegerContext<'a, W, N> {
    pub(crate) fn assign_int_mul_core<'b>(
        &mut self,
        a: &'b AssignedInteger<W, N>,
        b: &'b AssignedInteger<W, N>,
        d: &'b [Option<AssignedValue<N>>],
        rem: &'b AssignedInteger<W, N>,
    ) -> Result<(), Error> {
        let region = self.plonk_region_context.borrow().region;
        let config = &self.int_mul_config;
        let info = self.info();

        region.assign_fixed(
            || "",
            config.sel,
            self.plonk_region_context.borrow().offset,
            || Ok(N::one()),
        )?;

        let equal_assign_list = [
            (&config.a, &a.limbs_le[..]),
            (&config.b, &b.limbs_le[..]),
            (&config.rem, &rem.limbs_le[..]),
            (&config.d, d),
        ];

        for (target, from) in equal_assign_list {
            for i in 0..self.info().limbs as usize {
                let (col, rot) = target[i];
                let cell = region.assign_advice(
                    || "",
                    config.vars[col],
                    self.plonk_region_context.borrow().offset + rot as usize,
                    || Ok(from[i].as_ref().unwrap().value().unwrap()),
                )?;

                region.constrain_equal(from[i].unwrap().cell(), cell.cell())?;
            }
        }

        // Calculate v_list
        let v_list_value = (|| {
            Some({
                let mut limbs_sum = vec![];
                for pos in 0..info.mul_check_limbs as usize {
                    let r_bound = usize::min(pos + 1, info.limbs as usize);
                    let l_bound = pos.checked_sub(info.limbs as usize - 1).unwrap_or(0);

                    let sum = (l_bound..r_bound)
                        .map(|i| -> Option<N> {
                            Some(
                                a.limbs_le[i].unwrap().value()?
                                    * b.limbs_le[pos - i].unwrap().value()?
                                    - d[i].unwrap().value()? * info.w_modulus_limbs_le[pos - i],
                            )
                        })
                        .reduce(|acc, x| Some(acc? + x?))
                        .unwrap()?;

                    limbs_sum.push(sum);
                }

                let mut v_list_value: Vec<(N, N)> = vec![];

                let borrow = N::from(info.limbs) * info.limb_modulus_n + N::from(2u64);
                {
                    let u = limbs_sum[0] - rem.limbs_le[0].unwrap().value()?
                        + borrow * info.limb_modulus_n;
                    let u_bn = field_to_bn(&u);
                    v_list_value.push((
                        get_bn_compact_range_to_field(&u_bn, 2),
                        get_bn_compact_range_to_field(&u_bn, 1),
                    ));
                }

                let borrow = borrow * info.limb_modulus_n - borrow;
                for i in 1..info.limbs as usize {
                    let u = limbs_sum[i].clone() - rem.limbs_le[i].unwrap().value()?
                        + v_list_value[i - 1].0 * info.limb_coeffs[1]
                        + v_list_value[i - 1].1 * info.limb_coeffs[0]
                        + borrow;
                    let u_bn = field_to_bn(&u);
                    v_list_value.push((
                        get_bn_compact_range_to_field(&u_bn, 2),
                        get_bn_compact_range_to_field(&u_bn, 1),
                    ));
                }

                for i in info.limbs as usize..info.mul_check_limbs as usize {
                    let u = limbs_sum[i].clone()
                        + v_list_value[i - 1].0 * info.limb_coeffs[1]
                        + v_list_value[i - 1].1 * info.limb_coeffs[0]
                        + borrow;
                    let u_bn = field_to_bn(&u);
                    v_list_value.push((
                        get_bn_compact_range_to_field(&u_bn, 2),
                        get_bn_compact_range_to_field(&u_bn, 1),
                    ));
                }

                v_list_value
            })
        })();

        for i in 0..info.mul_check_limbs as usize {
            let v_h = self
                .range_region_context
                .borrow_mut()
                .assign_common_range_cell(v_list_value.as_ref().map(|x| x[i].0))?;
            let v_l = self
                .range_region_context
                .borrow_mut()
                .assign_compact_cell(v_list_value.as_ref().map(|x| x[i].1))?;

            let (col, rot) = config.v_list[i].0;
            let cell = region.assign_advice(
                || "",
                config.vars[col],
                self.plonk_region_context.borrow().offset + rot as usize,
                || Ok(v_h.value().unwrap()),
            )?;
            region.constrain_equal(cell.cell(), v_h.cell())?;

            let (col, rot) = config.v_list[i].1;
            let cell = region.assign_advice(
                || "",
                config.vars[col],
                self.plonk_region_context.borrow().offset + rot as usize,
                || Ok(v_l.value().unwrap()),
            )?;
            region.constrain_equal(cell.cell(), v_l.cell())?;
        }

        self.plonk_region_context.borrow_mut().offset += self.int_mul_config.block_rows;

        Ok(())
    }
}

use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::pairing::group::ff::PrimeField;
use halo2_proofs::pairing::group::Curve;
use halo2_proofs::plonk::Error;
use num_integer::Integer;
use rayon::iter::IntoParallelRefMutIterator as _;
use rayon::iter::ParallelIterator as _;
use std::ops::Sub;

use crate::assign::*;
use crate::chips::ecc_chip::EccChipBaseOps;
use crate::chips::native_chip::NativeChipOps;
use crate::context::NativeEccContext;
use crate::pair;
use crate::util::*;

use super::bit_chip::BitChipOps;
use super::ecc_chip::EccUnsafeError;

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
}

pub trait ParallelClone: Sized {
    fn apply_offset_diff(&mut self, offset_diff: &Offset);
    // WARNING: clone() doesn't clone permutation relationship, so we have to use merge() to collect them
    fn clone_with_offset(&self, offset_diff: &Offset) -> Self;
    fn clone_without_offset(&self) -> Self {
        self.clone_with_offset(&Offset {
            plonk_region_offset: 0,
            range_region_offset: 0,
        })
    }
    fn offset(&self) -> Offset;
    fn merge(&mut self, other: Self);
}

pub const MSM_PREFIX_OFFSET: u64 = 1 << 16;

impl<'b, C: CurveAffine> ParallelClone for NativeEccContext<'b, C> {
    fn apply_offset_diff(&mut self, offset_diff: &Offset) {
        self.get_plonk_region_context().offset += offset_diff.plonk_region_offset;
        self.get_range_region_context().offset += offset_diff.range_region_offset;
    }

    fn clone_with_offset(&self, offset_diff: &Offset) -> Self {
        let mut new_context = self.clone();

        new_context.get_plonk_region_context().offset += offset_diff.plonk_region_offset;
        new_context.get_range_region_context().offset += offset_diff.range_region_offset;
        new_context.get_range_region_context().compact_rows.clear();
        new_context
            .get_range_region_context()
            .compact_values
            .clear();
        new_context
            .get_range_region_context()
            .free_common_cells
            .clear();
        new_context.integer_context.int_mul_queue.clear();

        new_context
    }

    fn offset(&self) -> Offset {
        Offset {
            plonk_region_offset: self.integer_context.plonk_region_context.offset,
            range_region_offset: self.integer_context.range_region_context.offset,
        }
    }

    fn merge(&mut self, mut other: Self) {
        self.get_range_region_context()
            .compact_rows
            .append(&mut other.get_range_region_context().compact_rows);
        self.get_range_region_context()
            .compact_values
            .append(&mut other.get_range_region_context().compact_values);
        self.get_range_region_context()
            .free_common_cells
            .append(&mut other.get_range_region_context().free_common_cells);
        self.integer_context
            .int_mul_queue
            .append(&mut other.integer_context.int_mul_queue);
    }
}

impl<'b, C: CurveAffine> EccChipMSMOps<'b, C, C::Scalar> for NativeEccContext<'b, C> {
    type AssignedScalar = AssignedValue<C::Scalar>;

    fn get_and_increase_msm_prefix(&mut self) -> u64 {
        let msm_index = self.msm_index;
        self.msm_index += 1;
        msm_index * MSM_PREFIX_OFFSET
    }

    fn decompose_scalar<const WINDOW_SIZE: usize>(
        &mut self,
        s: &Self::AssignedScalar,
    ) -> Result<Vec<[AssignedCondition<C::Scalar>; WINDOW_SIZE]>, Error> {
        let one = C::Scalar::one();
        let two = one + &one;
        let four = two + &two;

        let mut bits = vec![];

        //TODO: replace with option
        let s_bn = field_to_bn(&s.value().unwrap_or(C::Scalar::zero()));
        let mut v = s.clone();

        for i in 0..<C::ScalarExt as PrimeField>::NUM_BITS as u64 / 2 {
            let b0 = if s_bn.bit(i * 2) {
                C::ScalarExt::one()
            } else {
                C::ScalarExt::zero()
            };
            let b1 = if s_bn.bit(i * 2 + 1) {
                C::ScalarExt::one()
            } else {
                C::ScalarExt::zero()
            };
            let b0 = self.plonk_region_context().assign_bit(b0)?;
            let b1 = self.plonk_region_context().assign_bit(b1)?;
            let v_next: C::ScalarExt = bn_to_field(&(&s_bn >> (i * 2 + 2)));

            let cells = self.plonk_region_context().one_line(
                [
                    pair!(&v_next, four),
                    pair!(b1.as_ref(), two),
                    pair!(b0.as_ref(), one),
                    pair!(&v, -one),
                ]
                .into_iter(),
                None,
                ([], None),
            )?;

            v = cells[0].unwrap();

            bits.push(b0);
            bits.push(b1);
        }

        if <C::ScalarExt as PrimeField>::NUM_BITS.is_odd() {
            self.plonk_region_context().assert_bit(&v)?;
            bits.push(v.into());
        } else {
            self.plonk_region_context()
                .assert_equal_constant(&v, C::Scalar::zero())?;
        }

        let rem = <C::ScalarExt as PrimeField>::NUM_BITS as usize % WINDOW_SIZE;
        if rem > 0 {
            let zero = self
                .plonk_region_context()
                .assign_constant(C::ScalarExt::zero())?;
            for _ in 0..WINDOW_SIZE - rem {
                bits.push(zero.into());
            }
        }

        let mut res: Vec<_> = bits
            .chunks(WINDOW_SIZE)
            .into_iter()
            .map(|x| x.try_into().unwrap())
            .collect();
        res.reverse();

        Ok(res)
    }

    fn ecc_bisec_scalar(
        &mut self,
        cond: &AssignedCondition<C::Scalar>,
        a: &Self::AssignedScalar,
        b: &Self::AssignedScalar,
    ) -> Result<Self::AssignedScalar, Error> {
        self.plonk_region_context().bisec(cond, a, b)
    }

    fn ecc_assign_constant_zero_scalar(&mut self) -> Result<Self::AssignedScalar, Error> {
        self.plonk_region_context()
            .assign_constant(C::Scalar::zero())
    }
}

pub trait EccChipMSMOps<'a, C: CurveAffine, N: FieldExt>:
    EccChipBaseOps<'a, C, N> + ParallelClone + Send + Sized
{
    type AssignedScalar: Clone;

    fn get_and_increase_msm_prefix(&mut self) -> u64;

    fn decompose_scalar<const WINDOW_SIZE: usize>(
        &mut self,
        s: &Self::AssignedScalar,
    ) -> Result<Vec<[AssignedCondition<N>; WINDOW_SIZE]>, Error>;

    fn msm_batch_on_group_non_zero_with_select_chip(
        &mut self,
        points: &Vec<AssignedNonZeroPoint<C, N>>,
        scalars: &Vec<Self::AssignedScalar>,
        rand_acc_point: C,
        rand_line_point: C,
    ) -> Result<AssignedPoint<C, N>, EccUnsafeError> {
        assert!(points.len() as u64 <= MSM_PREFIX_OFFSET);

        // Reduce points for parallel setup optimization.
        let points = points
            .iter()
            .map(|p| self.ecc_reduce_non_zero(p))
            .collect::<Result<Vec<_>, _>>()?;

        let rand_acc_point = self.assign_non_zero_point(Some(rand_acc_point))?;
        let rand_line_point = self.assign_non_zero_point(Some(rand_line_point))?;

        let rand_acc_point_neg = self.ecc_neg_non_zero(&rand_acc_point)?;
        let rand_acc_point_neg = self.ecc_reduce_non_zero(&rand_acc_point_neg)?;
        let rand_line_point_neg = self.ecc_neg_non_zero(&rand_line_point)?;
        let rand_line_point_neg = self.ecc_reduce_non_zero(&rand_line_point_neg)?;

        let best_group_size = 6;
        let n_group = (points.len() + best_group_size - 1) / best_group_size;
        let group_size = (points.len() + n_group - 1) / n_group;

        let mut constants = vec![];
        {
            let mut v = N::zero();
            for _ in 0..1 << group_size {
                constants.push(self.plonk_region_context().assign_constant(v)?);
                v += N::one();
            }
        }

        // Prepare candidation points for each group.
        let mut candidates = vec![];
        let group_prefix = self.get_and_increase_msm_prefix();

        for (group_index, chunk) in points.chunks(group_size).enumerate() {
            let init = if group_index.is_even() {
                &rand_line_point
            } else {
                &rand_line_point_neg
            };

            candidates.push(vec![init.clone()]);
            self.kvmap_set_ecc_non_zero(group_prefix + group_index as u64, &constants[0], &init)?;

            let cl = candidates.last_mut().unwrap();
            for i in 1..1u32 << chunk.len() {
                let pos = i.reverse_bits().leading_zeros(); // find the last bit-1 position
                let other = i - (1 << pos);
                let p = self.ecc_add_unsafe(&cl[other as usize], &chunk[pos as usize])?;
                let p = self.ecc_reduce_non_zero(&p)?;

                self.kvmap_set_ecc_non_zero(
                    group_prefix + group_index as u64,
                    &constants[i as usize],
                    &p,
                )?;
                cl.push(p);
            }
        }

        // Decompose to get bits of each (window, group).
        let bits = scalars
            .into_iter()
            .map(|s| self.decompose_scalar::<1>(s))
            .collect::<Result<Vec<Vec<[AssignedCondition<_>; 1]>>, _>>()?;

        let groups = bits.chunks(group_size).collect::<Vec<_>>();

        // Accumulate points of all groups in each window.
        let windows = bits[0].len();

        // For parallel setup, we calculate the offset change on first round.
        // The diff should be same because all point are normalized.
        let mut predict_ops = self.clone_without_offset();
        let offset_before = predict_ops.offset();
        let mut line_acc_arr = {
            let mut acc = rand_acc_point_neg.clone();
            for group_index in 0..groups.len() {
                let group_bits = groups[group_index].iter().map(|bits| bits[0][0]).collect();
                let (index_cell, ci) =
                    predict_ops.pick_candidate_non_zero(&candidates[group_index], &group_bits)?;
                let ci = predict_ops.kvmap_get_ecc_non_zero(
                    group_index as u64 + group_prefix,
                    &index_cell,
                    &ci,
                )?;

                acc = predict_ops.ecc_add_unsafe(&ci, &acc)?;
            }
            vec![acc]
        };
        let offset_after = predict_ops.offset();
        let offset_diff = offset_after - offset_before;
        self.merge(predict_ops);

        // Parallel setup on window.
        let mut cloned_ops = (1..windows)
            .into_iter()
            .map(|i| (i, self.clone_with_offset(&offset_diff.scale(i))))
            .collect::<Vec<_>>();

        let mut rest_line_acc_arr = cloned_ops
            .par_iter_mut()
            .map(
                |(wi, op)| -> Result<AssignedNonZeroPoint<C, N>, EccUnsafeError> {
                    let offset_before = op.offset();
                    let mut acc = rand_acc_point_neg.clone();
                    for group_index in 0..groups.len() {
                        let group_bits = groups[group_index]
                            .iter()
                            .map(|bits| bits[*wi][0])
                            .collect();
                        let (index_cell, ci) =
                            op.pick_candidate_non_zero(&candidates[group_index], &group_bits)?;
                        let ci = op.kvmap_get_ecc_non_zero(
                            group_index as u64 + group_prefix,
                            &index_cell,
                            &ci,
                        )?;

                        acc = op.ecc_add_unsafe(&ci, &acc)?;
                    }
                    let offset_after = op.offset();
                    let _offset_diff = offset_after - offset_before;
                    assert_eq!(offset_diff, _offset_diff);

                    Ok(acc)
                },
            )
            .collect::<Result<Vec<_>, _>>()?;
        line_acc_arr.append(&mut rest_line_acc_arr);
        drop(rest_line_acc_arr);

        for (_, op) in cloned_ops {
            self.merge(op);
        }

        // Set self offset to the tail and merge.
        self.apply_offset_diff(&offset_diff.scale(windows));

        // Accumulate points of all windows.
        let mut acc = rand_acc_point.clone();
        for wi in 0..windows {
            acc = self.ecc_double_unsafe(&acc)?;
            acc = self.ecc_add_unsafe(&line_acc_arr[wi], &acc)?;
            if groups.len().is_odd() {
                acc = self.ecc_add_unsafe(&acc, &rand_line_point_neg)?;
            }
        }

        // downgrade before add in case that result is identity
        let acc = self.ecc_non_zero_point_downgrade(&acc)?;
        let carry = self.ecc_non_zero_point_downgrade(&rand_acc_point_neg)?;
        let res = self.ecc_add(&acc, &carry)?;

        Ok(res)
    }

    fn msm_unsafe(
        &mut self,
        points: &Vec<AssignedPoint<C, N>>,
        scalars: &Vec<Self::AssignedScalar>,
    ) -> Result<AssignedPoint<C, N>, EccUnsafeError> {
        let r1 = (C::generator() * C::Scalar::rand()).to_affine();
        let r2 = (C::generator() * C::Scalar::rand()).to_affine();

        let mut non_zero_points = vec![];
        let mut normalized_scalars = vec![];
        let non_zero_p = self.assign_non_zero_point(Some(C::generator()))?;
        let s_zero = self.ecc_assign_constant_zero_scalar()?;

        for (p, s) in points.iter().zip(scalars.iter()) {
            let s = self.ecc_bisec_scalar(&p.z, &s_zero, s)?;
            let p = self.ecc_bisec_to_non_zero_point(p, &non_zero_p)?;
            non_zero_points.push(p);
            normalized_scalars.push(s);
        }

        let p = self.msm_batch_on_group_non_zero_with_select_chip(
            &non_zero_points,
            &normalized_scalars,
            r1,
            r2,
        )?;

        Ok(p)
    }

    fn msm(
        &mut self,
        points: &Vec<AssignedPoint<C, N>>,
        scalars: &Vec<Self::AssignedScalar>,
    ) -> Result<AssignedPoint<C, N>, EccUnsafeError> {
        self.msm_unsafe(points, scalars)
    }

    fn ecc_mul(&mut self, a: &AssignedPoint<C, N>, s: Self::AssignedScalar) -> AssignedPoint<C, N> {
        self.msm_unsafe(&vec![a.clone()], &vec![s.clone()]).unwrap()
    }

    fn ecc_bisec_scalar(
        &mut self,
        cond: &AssignedCondition<N>,
        a: &Self::AssignedScalar,
        b: &Self::AssignedScalar,
    ) -> Result<Self::AssignedScalar, Error>;

    fn ecc_assign_constant_zero_scalar(&mut self) -> Result<Self::AssignedScalar, Error>;
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use super::*;
    use crate::chips::msm_chip::EccChipMSMOps;
    use crate::chips::msm_chip::ParallelClone;
    use crate::context::PlonkRegionContext;
    use crate::context::RangeRegionContext;
    use crate::int_mul_gate::IntMulGate;
    use crate::int_mul_gate::IntMulGateConfig;
    use crate::kvmap_gate::KVMapGate;
    use crate::kvmap_gate::KVMapGateConfig;
    use crate::plonk_gate::*;
    use crate::range_gate::RangeGate;
    use crate::range_gate::RangeGateConfig;
    use crate::range_info::RangeInfo;
    use crate::util::test::*;
    use ark_std::{end_timer, start_timer};
    use floor_planner::V1;
    use halo2_proofs::arithmetic::BaseExt;
    use halo2_proofs::circuit::*;
    use halo2_proofs::pairing::bn256::G1Affine;
    use halo2_proofs::pairing::bn256::{Fq, Fr};
    use halo2_proofs::pairing::group::cofactor::CofactorCurveAffine;
    use halo2_proofs::plonk::*;
    use rand_core::OsRng;

    #[derive(Clone, Debug)]
    struct TestCircuit<F: Clone + Fn(&mut NativeEccContext<'_, G1Affine>) -> Result<(), Error>> {
        fill: F,
    }

    impl<F: Clone + Fn(&mut NativeEccContext<'_, G1Affine>) -> Result<(), Error>> Circuit<Fr>
        for TestCircuit<F>
    {
        type Config = (
            PlonkGateConfig,
            RangeGateConfig,
            IntMulGateConfig,
            KVMapGateConfig,
        );
        type FloorPlanner = V1;

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            let plonk_gate_config = PlonkGate::<Fr>::configure(meta);
            let range_gate_config = RangeGate::configure(meta);
            let int_mul_gate_config =
                IntMulGate::configure(meta, plonk_gate_config.var, &RangeInfo::<Fq, Fr>::new());
            let kvmap_gate_config =
                KVMapGate::configure(meta, plonk_gate_config.var[0..2].try_into().unwrap());
            (
                plonk_gate_config,
                range_gate_config,
                int_mul_gate_config,
                kvmap_gate_config,
            )
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
                || "test",
                |region| {
                    let plonk_region_context =
                        PlonkRegionContext::new_with_kvmap(&region, &config.0, &config.3);
                    let range_region_context = RangeRegionContext::new(&region, &config.1);
                    let mut native_ecc_context = NativeEccContext::new(
                        plonk_region_context,
                        range_region_context,
                        &config.2,
                        Arc::new(RangeInfo::new()),
                    );

                    native_ecc_context
                        .integer_context
                        .range_region_context
                        .init()?;
                    (self.fill)(&mut native_ecc_context)?;

                    let timer = start_timer!(|| "finalize_int_mul");
                    native_ecc_context.integer_context.finalize_int_mul()?;
                    end_timer!(timer);

                    let timer = start_timer!(|| "finalize_compact_cells");
                    native_ecc_context
                        .integer_context
                        .range_region_context
                        .finalize_compact_cells()?;
                    end_timer!(timer);

                    Ok(())
                },
            )?;
            end_timer!(timer);
            Ok(())
        }
    }

    fn fill_msm_test(
        context: &mut NativeEccContext<'_, G1Affine>,
        is_success: bool,
    ) -> Result<(), Error> {
        if is_success {
            let mut points = vec![];
            let mut scalars = vec![];

            let mut acc = G1Affine::identity().to_curve();
            for _ in 0..200 {
                let p = G1Affine::random(OsRng);
                let s = Fr::rand();
                points.push(context.assign_point(Some(p))?);
                scalars.push(context.plonk_region_context().assign(s)?);
                acc = acc + p * s;
            }

            let timer = start_timer!(|| "msm");
            let p = context.msm(&points, &scalars).unwrap();
            end_timer!(timer);

            let acc = context.assign_point(Some(acc.to_affine()))?;
            context.ecc_assert_equal(&p, &acc)?;

            println!("offset is {:?}", context.offset());
        } else {
            unimplemented!()
        }
        Ok(())
    }

    #[test]
    fn test_msm_chip_success() {
        run_circuit_on_bn256(
            TestCircuit {
                fill: |context| {
                    let is_success = true;

                    for v in [fill_msm_test] {
                        v(context, is_success)?;
                    }

                    Ok(())
                },
            },
            22,
        );
    }

    #[test]
    #[cfg(feature = "profile")]
    fn bench_msm_chip_success() {
        bench_circuit_on_bn256(
            TestCircuit {
                fill: |context| {
                    let is_success = true;

                    for v in [fill_msm_test] {
                        v(context, is_success)?;
                    }

                    Ok(())
                },
            },
            22,
        );
    }

    /*
    #[test]
    fn test_int_chip_fail1() {
        macro_rules! test_fail {
            ($f: expr) => {
                run_circuit_on_bn256_expect_fail(
                    TestCircuit {
                        fill: |context| $f(context, false),
                    },
                    19,
                );
            };
        }
        for _ in 0..10 {
            for v in [
                fill_msm_test
            ] {
                test_fail!(v);
            }
        }
    }
    */
}

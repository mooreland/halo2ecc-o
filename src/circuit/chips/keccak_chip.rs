use crate::{
    assign::{AssignedCondition, AssignedValue},
    context::PlonkRegionContext,
    pair,
    util::*,
};
use halo2_proofs::{arithmetic::FieldExt, plonk::Error};

use super::{bit_chip::BitChipOps as _, native_chip::NativeChipOps as _};

const T: usize = 5;
const W: usize = 64;
pub const ABSORB_BITS_RATE: usize = 1088;

pub type AssignedState<N> = [[[AssignedCondition<N>; W]; T]; T];

const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

pub const N_R: usize = T * T - 1;

pub static ROUND_CONSTANTS: [u64; N_R] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

pub trait KeccakChipOps<'a, N: FieldExt> {
    fn plonk_region_context(&mut self) -> &mut PlonkRegionContext<'a, N>;
    fn init(&mut self) -> Result<AssignedState<N>, Error> {
        let zero = self
            .plonk_region_context()
            .assign_constant(N::zero())?
            .into();
        let state = [[[zero; W]; T]; T];
        Ok(state)
    }

    fn theta(&mut self, state: &mut AssignedState<N>) -> Result<(), Error> {
        let mut c = state[0].clone();

        let prev = |x: usize| (x + 4) % 5;
        let next = |x: usize| (x + 1) % 5;

        for x in 0..T {
            let y = &state[x];
            let mut ci = y[0].clone();
            for i in 1..T {
                for z in 0..W {
                    ci[z] = self.plonk_region_context().xor(&ci[z], &y[i][z])?;
                }
            }
            c[x] = ci;
        }

        for x in 0..T {
            let mut di = c[next(x)].clone();
            di.rotate_left(1);
            for z in 0..W {
                di[z] = self.plonk_region_context().xor(&c[prev(x)][z], &di[z])?;
            }
            for y in 0..T {
                for z in 0..W {
                    state[x][y][z] = self.plonk_region_context().xor(&state[x][y][z], &di[z])?;
                }
            }
        }

        Ok(())
    }

    fn rho_and_pi(&mut self, state: &mut AssignedState<N>) -> Result<(), Error> {
        let mut last = state[1][0].clone();
        for i in 0..N_R {
            let pi_x = PI[i] % 5;
            let pi_y = PI[i] / 5;
            let array = state[pi_x][pi_y].clone();
            last.rotate_left(RHO[i] as usize);
            state[pi_x][pi_y].copy_from_slice(&last[..]);
            last = array;
        }
        Ok(())
    }

    fn xi(&mut self, state: &mut AssignedState<N>) -> Result<(), Error> {
        let next = |x: usize| (x + 1) % 5;
        let skip = |x: usize| (x + 2) % 5;

        let mut out = state.clone();

        for x in 0..T {
            for y in 0..T {
                for z in 0..W {
                    let t = self
                        .plonk_region_context()
                        .not_and(&state[next(x)][y][z], &state[skip(x)][y][z])?;
                    out[x][y][z] = self.plonk_region_context().xor(&state[x][y][z], &t)?;
                }
            }
        }

        *state = out;
        Ok(())
    }

    fn iota(&mut self, state: &mut AssignedState<N>, round: usize) -> Result<(), Error> {
        for z in 0..W {
            // xor_const(a, b) = if b is 0 { a } else { not(a) }
            // The state bit is BE
            if ROUND_CONSTANTS[round] & (1 << (W - z - 1)) != 0 {
                state[0][0][z] = self.plonk_region_context().not(&state[0][0][z])?;
            }
        }
        Ok(())
    }

    fn permute(&mut self, state: &mut AssignedState<N>) -> Result<(), Error> {
        for i in 0..N_R {
            self.theta(state)?;
            self.rho_and_pi(state)?;
            self.xi(state)?;
            self.iota(state, i)?;
        }
        Ok(())
    }

    fn absorb(
        &mut self,
        state: &mut AssignedState<N>,
        input: &[AssignedCondition<N>],
    ) -> Result<(), Error> {
        assert!(input.len() == ABSORB_BITS_RATE);
        let mut x = 0;
        let mut y = 0;
        const W_BYTES: usize = W / 8;
        for i in 0..ABSORB_BITS_RATE / W {
            for j in 0..W_BYTES {
                for k in 0..8 {
                    // For different endian
                    let z = i * W + j * 8 + k;
                    let permuted_z = (W_BYTES - j - 1) * 8 + k;
                    state[x][y][permuted_z] = self
                        .plonk_region_context()
                        .xor(&input[z], &state[x][y][permuted_z])?;
                }
            }
            if x < T - 1 {
                x += 1;
            } else {
                y += 1;
                x = 0;
            }
        }
        self.permute(state)?;
        Ok(())
    }

    // We don't care that decomposed value is larger than modulus, because the u256 should be used as scalar.
    fn decompose_scalar_as_u256_be(
        &mut self,
        s: &AssignedValue<N>,
    ) -> Result<[AssignedCondition<N>; 256], Error> {
        let one = N::one();
        let two = one + &one;
        let four = two + &two;

        let mut bits: Vec<AssignedCondition<N>> = vec![];

        let s_bn = s.value.map(|v| field_to_bn(&v));
        let mut v = s.clone();

        for i in 0..256 / 2 {
            let (b01, v_next) = (|| {
                Some({
                    let b0 = if s_bn.as_ref()?.bit(i * 2) {
                        N::one()
                    } else {
                        N::zero()
                    };
                    let b1 = if s_bn.as_ref()?.bit(i * 2 + 1) {
                        N::one()
                    } else {
                        N::zero()
                    };
                    let v_next = bn_to_field(&(s_bn.as_ref()? >> (i * 2 + 2)));
                    ((b0, b1), v_next)
                })
            })()
            .unzip();
            let (b0, b1) = b01.unzip();

            let b0 = self.plonk_region_context().assign_bit_opt(b0)?;
            let b1 = self.plonk_region_context().assign_bit_opt(b1)?;

            let cells = self.plonk_region_context().one_line(
                [
                    pair!(&v_next.clone(), four),
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

        self.plonk_region_context()
            .assert_equal_constant(&v, N::zero())?;
        bits.reverse();

        let res: [AssignedCondition<N>; 256] = bits.try_into().unwrap();
        Ok(res)
    }

    fn compose_to_scalar_be(
        &mut self,
        s: &[AssignedCondition<N>],
    ) -> Result<AssignedValue<N>, Error> {
        assert!(s.len() % 2 == 0);
        let mut acc = self.plonk_region_context().assign_constant(N::zero())?;

        let one = N::one();
        let two = one + &one;
        let four = two + &two;

        for i in 0..s.len() / 2 {
            let b0 = s[i * 2 + 1];
            let b1 = s[i * 2];

            acc = self.plonk_region_context().sum_with_constant(
                &[(b0.as_ref(), one), (b1.as_ref(), two), (&acc, four)],
                None,
            )?;
        }

        Ok(acc)
    }

    fn hash(&mut self, input: &[AssignedValue<N>]) -> Result<AssignedValue<N>, Error> {
        let assigned_one: AssignedCondition<_> = self
            .plonk_region_context()
            .assign_constant(N::one())?
            .into();
        let assigned_zero: AssignedCondition<_> = self
            .plonk_region_context()
            .assign_constant(N::zero())?
            .into();
        let mut state = self.init()?;

        let raw_len = input.len() * 256;
        let mut input_bits = vec![];
        for v in input {
            input_bits.extend_from_slice(&self.decompose_scalar_as_u256_be(v)?[..]);
        }

        let aligned_len =
            (raw_len + 8 + ABSORB_BITS_RATE - 1) / ABSORB_BITS_RATE * ABSORB_BITS_RATE;
        let padding_len = aligned_len - raw_len;

        if padding_len == 8 {
            // padding 0x81
            input_bits.push(assigned_one.clone());
            input_bits.push(assigned_zero.clone());
            input_bits.push(assigned_zero.clone());
            input_bits.push(assigned_zero.clone());
            input_bits.push(assigned_zero.clone());
            input_bits.push(assigned_zero.clone());
            input_bits.push(assigned_zero.clone());
            input_bits.push(assigned_one.clone());
        } else {
            // padding 0x01
            input_bits.push(assigned_zero.clone());
            input_bits.push(assigned_zero.clone());
            input_bits.push(assigned_zero.clone());
            input_bits.push(assigned_zero.clone());
            input_bits.push(assigned_zero.clone());
            input_bits.push(assigned_zero.clone());
            input_bits.push(assigned_zero.clone());
            input_bits.push(assigned_one.clone());

            // padding zero
            for _ in 0..padding_len - 16 {
                input_bits.push(assigned_zero.clone());
            }

            // padding 0x80
            input_bits.push(assigned_one.clone());
            input_bits.push(assigned_zero.clone());
            input_bits.push(assigned_zero.clone());
            input_bits.push(assigned_zero.clone());
            input_bits.push(assigned_zero.clone());
            input_bits.push(assigned_zero.clone());
            input_bits.push(assigned_zero.clone());
            input_bits.push(assigned_zero.clone());
        }

        for c in input_bits.chunks_exact(ABSORB_BITS_RATE) {
            self.absorb(&mut state, &c)?;
        }

        let res_bits = vec![state[0][0], state[1][0], state[2][0], state[3][0]]
            .into_iter()
            .map(|x| {
                x.chunks_exact(8)
                    .rev()
                    .flatten()
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
            .concat();

        self.compose_to_scalar_be(&res_bits[..])
    }
}

impl<'a, N: FieldExt> PlonkRegionContext<'a, N> {}

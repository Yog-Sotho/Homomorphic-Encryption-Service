//! Programs: several operations evaluated in one job.
//!
//! A [`Program`] is a list of [`Step`]s. Each step applies a [`ProgramOp`] to
//! arguments that are job inputs, results of earlier steps, or plaintext
//! constants; the last step is the job's result. Every intermediate value stays
//! encrypted on the server. [`Program::check`] type-checks a program for an
//! integer type and an input count, and [`CheckedProgram::eval_plain`] gives the
//! plaintext result the decrypted homomorphic one must equal.
//!
//! [`parse_expression`](crate::parse_expression) compiles a small expression
//! syntax (`(a + b) * 3 < c ? a : b`) into a program.

use crate::params::{MAX_INPUTS, MAX_PROGRAM_STEPS};
use crate::types::{IntegerType, PlainValue, ValueType};
use serde::{Deserialize, Serialize};
use std::fmt;

/// An argument of a step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum Arg {
    /// The job's encrypted input with this index (0-based).
    Input(usize),
    /// The result of an earlier step (0-based).
    Step(usize),
    /// A plaintext constant in decimal, e.g. `"-3"`. The server sees it.
    Const(String),
}

/// What a step computes. Arithmetic wraps modulo 2^bits of the program's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum ProgramOp {
    Add,
    Subtract,
    Multiply,
    /// Truncating division. By an encrypted zero: the type's maximum (unsigned),
    /// or −1 / 1 for a non-negative / negative dividend (signed); `MIN / −1` is
    /// `MIN`. A constant divisor must not be zero.
    Divide,
    /// The remainder of [`Divide`](Self::Divide), with the dividend's sign. By an
    /// encrypted zero: the dividend.
    Remainder,
    Min,
    Max,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    /// Bitwise on integers, logical on booleans.
    And,
    Or,
    Xor,
    /// Bitwise complement on integers, negation on booleans.
    Not,
    /// Two's-complement negation (wrapping).
    Neg,
    /// Absolute value of a signed integer (`MIN` stays `MIN`).
    Abs,
    /// Shifts and rotations by a constant number of bits (0 to bits − 1).
    /// `shr` is arithmetic on signed types.
    Shl,
    Shr,
    Rotl,
    Rotr,
    /// `select(condition, if_true, if_false)`: an encrypted if-then-else.
    Select,
}

impl ProgramOp {
    pub const ALL: [ProgramOp; 24] = [
        ProgramOp::Add,
        ProgramOp::Subtract,
        ProgramOp::Multiply,
        ProgramOp::Divide,
        ProgramOp::Remainder,
        ProgramOp::Min,
        ProgramOp::Max,
        ProgramOp::Eq,
        ProgramOp::Ne,
        ProgramOp::Lt,
        ProgramOp::Le,
        ProgramOp::Gt,
        ProgramOp::Ge,
        ProgramOp::And,
        ProgramOp::Or,
        ProgramOp::Xor,
        ProgramOp::Not,
        ProgramOp::Neg,
        ProgramOp::Abs,
        ProgramOp::Shl,
        ProgramOp::Shr,
        ProgramOp::Rotl,
        ProgramOp::Rotr,
        ProgramOp::Select,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ProgramOp::Add => "add",
            ProgramOp::Subtract => "subtract",
            ProgramOp::Multiply => "multiply",
            ProgramOp::Divide => "divide",
            ProgramOp::Remainder => "remainder",
            ProgramOp::Min => "min",
            ProgramOp::Max => "max",
            ProgramOp::Eq => "eq",
            ProgramOp::Ne => "ne",
            ProgramOp::Lt => "lt",
            ProgramOp::Le => "le",
            ProgramOp::Gt => "gt",
            ProgramOp::Ge => "ge",
            ProgramOp::And => "and",
            ProgramOp::Or => "or",
            ProgramOp::Xor => "xor",
            ProgramOp::Not => "not",
            ProgramOp::Neg => "neg",
            ProgramOp::Abs => "abs",
            ProgramOp::Shl => "shl",
            ProgramOp::Shr => "shr",
            ProgramOp::Rotl => "rotl",
            ProgramOp::Rotr => "rotr",
            ProgramOp::Select => "select",
        }
    }

    fn is_comparison(self) -> bool {
        matches!(
            self,
            ProgramOp::Eq
                | ProgramOp::Ne
                | ProgramOp::Lt
                | ProgramOp::Le
                | ProgramOp::Gt
                | ProgramOp::Ge
        )
    }
}

impl fmt::Display for ProgramOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Step {
    pub op: ProgramOp,
    pub args: Vec<Arg>,
}

/// Steps evaluated in order; the last one is the result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Program {
    pub steps: Vec<Step>,
}

/// What a value in a program is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An integer of the program's type.
    Int,
    Bool,
}

/// A reference to an encrypted value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ref {
    Input(usize),
    Step(usize),
}

/// A checked argument: an encrypted value or a constant in the type's range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Value(Ref),
    Const(i128),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedStep {
    pub op: ProgramOp,
    pub args: Vec<Operand>,
    pub kind: Kind,
}

/// A program that passed [`Program::check`]: references point backwards,
/// constants are parsed and in range, and every step is well typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedProgram {
    pub integer_type: IntegerType,
    pub input_count: usize,
    pub steps: Vec<CheckedStep>,
}

impl Program {
    /// Type-checks the program for `input_count` encrypted inputs of type `ty`.
    /// The error names the step and is safe to show to the caller.
    pub fn check(&self, ty: IntegerType, input_count: usize) -> Result<CheckedProgram, String> {
        if self.steps.is_empty() || self.steps.len() > MAX_PROGRAM_STEPS {
            return Err(format!(
                "A program has 1 to {MAX_PROGRAM_STEPS} steps, not {}",
                self.steps.len()
            ));
        }
        if input_count == 0 || input_count > MAX_INPUTS {
            return Err(format!(
                "A program takes 1 to {MAX_INPUTS} encrypted inputs, not {input_count}"
            ));
        }
        let mut steps: Vec<CheckedStep> = Vec::with_capacity(self.steps.len());
        for (index, step) in self.steps.iter().enumerate() {
            let fail = |message: String| format!("Step {} ({}): {message}", index + 1, step.op);
            let mut args = Vec::with_capacity(step.args.len());
            for arg in &step.args {
                args.push(match arg {
                    Arg::Input(i) if *i < input_count => Operand::Value(Ref::Input(*i)),
                    Arg::Input(i) => {
                        return Err(fail(format!(
                            "there is no input {} (the job has {input_count})",
                            i + 1
                        )))
                    }
                    Arg::Step(s) if *s < index => Operand::Value(Ref::Step(*s)),
                    Arg::Step(s) => {
                        return Err(fail(format!("step {} is not an earlier step", s + 1)))
                    }
                    Arg::Const(text) => Operand::Const(ty.parse_value(text).map_err(fail)?),
                });
            }
            let kind_of = |operand: &Operand| match operand {
                Operand::Value(Ref::Input(_)) => Some(Kind::Int),
                Operand::Value(Ref::Step(s)) => Some(steps[*s].kind),
                Operand::Const(_) => None,
            };
            let kinds: Vec<Option<Kind>> = args.iter().map(kind_of).collect();
            let kind = step_kind(step.op, ty, &args, &kinds).map_err(fail)?;
            steps.push(CheckedStep {
                op: step.op,
                args,
                kind,
            });
        }
        Ok(CheckedProgram {
            integer_type: ty,
            input_count,
            steps,
        })
    }
}

/// The kind of a step's result, or why its arguments do not fit.
fn step_kind(
    op: ProgramOp,
    ty: IntegerType,
    args: &[Operand],
    kinds: &[Option<Kind>],
) -> Result<Kind, String> {
    use Kind::{Bool, Int};
    let arity = match op {
        ProgramOp::Not | ProgramOp::Neg | ProgramOp::Abs => 1,
        ProgramOp::Select => 3,
        _ => 2,
    };
    if args.len() != arity {
        return Err(format!(
            "takes {arity} argument{}, not {}",
            if arity == 1 { "" } else { "s" },
            args.len()
        ));
    }
    let first = kinds[0].ok_or("the first argument must be encrypted, not a constant")?;
    match op {
        ProgramOp::Not => Ok(first),
        ProgramOp::Neg | ProgramOp::Abs => {
            if first != Int {
                return Err("needs an integer".into());
            }
            if op == ProgramOp::Abs && !ty.is_signed() {
                return Err(format!("needs a signed type, not {ty}"));
            }
            Ok(Int)
        }
        ProgramOp::Select => {
            if first != Bool {
                return Err("the condition must be a boolean (a comparison)".into());
            }
            match (kinds[1], kinds[2]) {
                (Some(Int), Some(Int)) => Ok(Int),
                (None, _) | (_, None) => {
                    Err("both branches must be encrypted, not constants".into())
                }
                _ => Err("both branches must be integers".into()),
            }
        }
        ProgramOp::Shl | ProgramOp::Shr | ProgramOp::Rotl | ProgramOp::Rotr => {
            if first != Int {
                return Err("needs an integer".into());
            }
            match args[1] {
                Operand::Const(n) if (0..ty.bits() as i128).contains(&n) => Ok(Int),
                Operand::Const(n) => Err(format!("shifts by 0 to {} bits, not {n}", ty.bits() - 1)),
                Operand::Value(_) => Err("the shift amount must be a constant".into()),
            }
        }
        ProgramOp::And | ProgramOp::Or | ProgramOp::Xor if first == Bool => match kinds[1] {
            Some(Bool) => Ok(Bool),
            _ => Err("on booleans, both arguments must be encrypted booleans".into()),
        },
        _ => {
            if first != Int || kinds[1] == Some(Bool) {
                return Err("needs integers, not booleans".into());
            }
            if matches!(op, ProgramOp::Divide | ProgramOp::Remainder)
                && args[1] == Operand::Const(0)
            {
                return Err("cannot divide by the constant 0".into());
            }
            Ok(if op.is_comparison() { Bool } else { Int })
        }
    }
}

impl CheckedProgram {
    /// The type to decrypt the result as.
    pub fn result_type(&self) -> ValueType {
        match self.steps.last().map(|s| s.kind) {
            Some(Kind::Bool) => ValueType::Bool,
            _ => self.integer_type.into(),
        }
    }

    /// The plaintext result, for `inputs` in the type's range.
    pub fn eval_plain(&self, inputs: &[i128]) -> PlainValue {
        assert_eq!(inputs.len(), self.input_count, "wrong number of inputs");
        let ty = self.integer_type;
        let mut values: Vec<PlainValue> = Vec::with_capacity(self.steps.len());
        for step in &self.steps {
            let get = |operand: &Operand| match operand {
                Operand::Value(Ref::Input(i)) => PlainValue::Int(inputs[*i]),
                Operand::Value(Ref::Step(s)) => values[*s],
                Operand::Const(c) => PlainValue::Int(*c),
            };
            let args: Vec<PlainValue> = step.args.iter().map(get).collect();
            values.push(apply_plain(step.op, ty, &args));
        }
        *values.last().expect("a checked program has steps")
    }
}

fn int(value: PlainValue) -> i128 {
    match value {
        PlainValue::Int(v) => v,
        PlainValue::Bool(b) => b as i128,
    }
}

/// One step on plaintexts, with exactly the encrypted semantics.
fn apply_plain(op: ProgramOp, ty: IntegerType, args: &[PlainValue]) -> PlainValue {
    use PlainValue::{Bool, Int};
    match (op, args) {
        (ProgramOp::Select, [Bool(condition), if_true, if_false]) => {
            return if *condition { *if_true } else { *if_false };
        }
        (ProgramOp::Not, [Bool(a)]) => return Bool(!a),
        (ProgramOp::And, [Bool(a), Bool(b)]) => return Bool(*a && *b),
        (ProgramOp::Or, [Bool(a), Bool(b)]) => return Bool(*a || *b),
        (ProgramOp::Xor, [Bool(a), Bool(b)]) => return Bool(a != b),
        _ => {}
    }
    let a = int(args[0]);
    let b = args.get(1).map(|&v| int(v)).unwrap_or(0);
    let bits = ty.bits();
    let unsigned = |v: i128| (v as u128) & ((1u128 << bits) - 1);
    match op {
        ProgramOp::Add => Int(ty.wrap(a.wrapping_add(b))),
        ProgramOp::Subtract => Int(ty.wrap(a.wrapping_sub(b))),
        ProgramOp::Multiply => Int(ty.wrap(a.wrapping_mul(b))),
        ProgramOp::Divide | ProgramOp::Remainder => {
            let (q, r) = if b == 0 {
                let q = if !ty.is_signed() {
                    ty.max_value()
                } else if a >= 0 {
                    -1
                } else {
                    1
                };
                (q, a)
            } else {
                // i128 division truncates toward zero; MIN / -1 wraps to MIN.
                (ty.wrap(a / b), a % b)
            };
            Int(if op == ProgramOp::Divide { q } else { r })
        }
        ProgramOp::Min => Int(a.min(b)),
        ProgramOp::Max => Int(a.max(b)),
        ProgramOp::Eq => Bool(a == b),
        ProgramOp::Ne => Bool(a != b),
        ProgramOp::Lt => Bool(a < b),
        ProgramOp::Le => Bool(a <= b),
        ProgramOp::Gt => Bool(a > b),
        ProgramOp::Ge => Bool(a >= b),
        ProgramOp::And => Int(ty.wrap(a & b)),
        ProgramOp::Or => Int(ty.wrap(a | b)),
        ProgramOp::Xor => Int(ty.wrap(a ^ b)),
        ProgramOp::Not => Int(ty.wrap(!a)),
        ProgramOp::Neg => Int(ty.wrap(a.wrapping_neg())),
        ProgramOp::Abs => Int(ty.wrap(a.abs())),
        ProgramOp::Shl => Int(ty.wrap(a << b)),
        // Arithmetic for signed values (i128 >>), logical for unsigned ones.
        ProgramOp::Shr => Int(a >> b),
        ProgramOp::Rotl | ProgramOp::Rotr => {
            let (u, n) = (unsigned(a), b as u32);
            let mask = (1u128 << bits) - 1;
            let rotated = if n == 0 {
                u
            } else if op == ProgramOp::Rotl {
                ((u << n) | (u >> (bits - n))) & mask
            } else {
                ((u >> n) | (u << (bits - n))) & mask
            };
            Int(ty.wrap(rotated as i128))
        }
        ProgramOp::Select => unreachable!("select takes a boolean condition"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use IntegerType::*;

    fn step(op: ProgramOp, args: Vec<Arg>) -> Step {
        Step { op, args }
    }

    fn c(v: &str) -> Arg {
        Arg::Const(v.into())
    }

    #[test]
    fn programs_are_type_checked_with_useful_errors() {
        let good = Program {
            steps: vec![
                step(ProgramOp::Add, vec![Arg::Input(0), Arg::Input(1)]),
                step(ProgramOp::Lt, vec![Arg::Step(0), c("100")]),
                step(
                    ProgramOp::Select,
                    vec![Arg::Step(1), Arg::Input(0), Arg::Step(0)],
                ),
            ],
        };
        let checked = good.check(U8, 2).unwrap();
        assert_eq!(checked.result_type(), ValueType::U8);
        assert_eq!(checked.eval_plain(&[30, 40]), PlainValue::Int(30));
        assert_eq!(checked.eval_plain(&[90, 40]), PlainValue::Int(130));

        let bad = |steps: Vec<Step>, inputs: usize, ty: IntegerType| {
            Program { steps }.check(ty, inputs).unwrap_err()
        };
        assert!(bad(vec![], 1, U8).contains("1 to"));
        assert!(bad(
            vec![step(ProgramOp::Add, vec![Arg::Input(0), Arg::Input(2)])],
            2,
            U8
        )
        .contains("no input 3"));
        assert!(bad(
            vec![step(ProgramOp::Add, vec![Arg::Input(0), Arg::Step(0)])],
            1,
            U8
        )
        .contains("not an earlier step"));
        assert!(bad(
            vec![step(ProgramOp::Add, vec![c("1"), Arg::Input(0)])],
            1,
            U8
        )
        .contains("first argument"));
        assert!(bad(
            vec![step(ProgramOp::Add, vec![Arg::Input(0), c("256")])],
            1,
            U8
        )
        .contains("outside"));
        assert!(bad(
            vec![step(ProgramOp::Divide, vec![Arg::Input(0), c("0")])],
            1,
            U8
        )
        .contains("constant 0"));
        assert!(bad(vec![step(ProgramOp::Abs, vec![Arg::Input(0)])], 1, U8).contains("signed"));
        assert!(bad(
            vec![step(ProgramOp::Shl, vec![Arg::Input(0), c("8")])],
            1,
            U8
        )
        .contains("0 to 7"));
        assert!(bad(
            vec![step(ProgramOp::Shl, vec![Arg::Input(0), Arg::Input(0)])],
            1,
            U8
        )
        .contains("constant"));
        assert!(bad(
            vec![step(
                ProgramOp::Select,
                vec![Arg::Input(0), Arg::Input(0), Arg::Input(0)]
            )],
            1,
            U8
        )
        .contains("condition"));
        assert!(bad(vec![step(ProgramOp::Not, vec![])], 1, U8).contains("takes 1 argument"));
        let compare_then_add = vec![
            step(ProgramOp::Eq, vec![Arg::Input(0), c("1")]),
            step(ProgramOp::Add, vec![Arg::Step(0), c("1")]),
        ];
        assert!(bad(compare_then_add, 1, U8).contains("not booleans"));
        let mixed_logic = vec![
            step(ProgramOp::Eq, vec![Arg::Input(0), c("1")]),
            step(ProgramOp::And, vec![Arg::Step(0), Arg::Input(0)]),
        ];
        assert!(bad(mixed_logic, 1, U8).contains("booleans"));
    }

    fn eval(op: ProgramOp, ty: IntegerType, args: &[i128]) -> i128 {
        let steps = vec![step(op, (0..args.len()).map(Arg::Input).collect())];
        match (Program { steps })
            .check(ty, args.len())
            .unwrap()
            .eval_plain(args)
        {
            PlainValue::Int(v) => v,
            PlainValue::Bool(b) => b as i128,
        }
    }

    #[test]
    fn division_follows_tfhe_rs_including_by_zero() {
        // Measured with TFHE-rs 1.8.2 (see the Phase 9 notes in the audit).
        assert_eq!(eval(ProgramOp::Divide, U8, &[7, 0]), 255);
        assert_eq!(eval(ProgramOp::Remainder, U8, &[7, 0]), 7);
        assert_eq!(eval(ProgramOp::Divide, U8, &[200, 7]), 28);
        assert_eq!(eval(ProgramOp::Remainder, U8, &[200, 7]), 4);
        assert_eq!(eval(ProgramOp::Divide, I8, &[7, 0]), -1);
        assert_eq!(eval(ProgramOp::Divide, I8, &[-7, 0]), 1);
        assert_eq!(eval(ProgramOp::Divide, I8, &[0, 0]), -1);
        assert_eq!(eval(ProgramOp::Remainder, I8, &[-7, 0]), -7);
        assert_eq!(eval(ProgramOp::Divide, I8, &[-128, -1]), -128);
        assert_eq!(eval(ProgramOp::Remainder, I8, &[-128, -1]), 0);
        assert_eq!(eval(ProgramOp::Divide, I8, &[-7, 2]), -3);
        assert_eq!(eval(ProgramOp::Remainder, I8, &[-7, 2]), -1);
        assert_eq!(eval(ProgramOp::Divide, I8, &[7, -2]), -3);
        assert_eq!(eval(ProgramOp::Remainder, I8, &[7, -2]), 1);
    }

    #[test]
    fn bitwise_shifts_and_rotations() {
        let x = 0b1011_0101;
        let shift = |op, n: u32| {
            let steps = vec![step(op, vec![Arg::Input(0), c(&n.to_string())])];
            match (Program { steps }).check(U8, 1).unwrap().eval_plain(&[x]) {
                PlainValue::Int(v) => v,
                other => panic!("{other:?}"),
            }
        };
        assert_eq!(shift(ProgramOp::Shl, 1), 106);
        assert_eq!(shift(ProgramOp::Shr, 1), 90);
        assert_eq!(shift(ProgramOp::Rotl, 1), 107);
        assert_eq!(shift(ProgramOp::Shl, 7), 128);
        assert_eq!(shift(ProgramOp::Rotr, 1), 218);
        assert_eq!(shift(ProgramOp::Rotl, 0), x);
        let steps = vec![step(ProgramOp::Shr, vec![Arg::Input(0), c("7")])];
        assert_eq!(
            (Program { steps }).check(I8, 1).unwrap().eval_plain(&[-75]),
            PlainValue::Int(-1)
        );
        assert_eq!(eval(ProgramOp::And, U8, &[0b1100, 0b1010]), 8);
        assert_eq!(eval(ProgramOp::Not, U8, &[0b1100]), 243);
        assert_eq!(eval(ProgramOp::Neg, U8, &[3]), 253);
        assert_eq!(eval(ProgramOp::Neg, I8, &[-128]), -128);
        assert_eq!(eval(ProgramOp::Abs, I8, &[-128]), -128);
        assert_eq!(eval(ProgramOp::Abs, I16, &[-300]), 300);
    }

    #[test]
    fn programs_round_trip_as_json() {
        let json = serde_json::json!({"steps": [
            {"op": "multiply", "args": [{"input": 0}, {"const": "-3"}]},
            {"op": "ge", "args": [{"step": 0}, {"input": 1}]}
        ]});
        let program: Program = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(&program).unwrap(), json);
        let checked = program.check(I32, 2).unwrap();
        assert_eq!(checked.result_type(), ValueType::Bool);
        assert_eq!(checked.eval_plain(&[5, -15]), PlainValue::Bool(true));
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        /// One step on native Rust integers: the reference for the oracle.
        fn native(op: ProgramOp, ty: IntegerType, a: i128, b: i128) -> i128 {
            macro_rules! with {
                ($t:ty, $signed:expr) => {{
                    let (x, y) = (a as $t, b as $t);
                    let n = b as u32;
                    (match op {
                        ProgramOp::Divide if y == 0 => {
                            if !$signed {
                                <$t>::MAX
                            } else if a >= 0 {
                                (0 as $t).wrapping_sub(1)
                            } else {
                                1
                            }
                        }
                        ProgramOp::Remainder if y == 0 => x,
                        ProgramOp::Divide => x.wrapping_div(y),
                        ProgramOp::Remainder => x.wrapping_rem(y),
                        ProgramOp::Shl => x.wrapping_shl(n),
                        ProgramOp::Shr => x.wrapping_shr(n),
                        ProgramOp::Rotl => x.rotate_left(n),
                        ProgramOp::Rotr => x.rotate_right(n),
                        ProgramOp::And => x & y,
                        ProgramOp::Or => x | y,
                        ProgramOp::Xor => x ^ y,
                        _ => unreachable!(),
                    }) as i128
                }};
            }
            match ty {
                U8 => with!(u8, false),
                U16 => with!(u16, false),
                U32 => with!(u32, false),
                U64 => with!(u64, false),
                I8 => with!(i8, true),
                I16 => with!(i16, true),
                I32 => with!(i32, true),
                I64 => with!(i64, true),
            }
        }

        const OPS: [ProgramOp; 9] = [
            ProgramOp::Divide,
            ProgramOp::Remainder,
            ProgramOp::Shl,
            ProgramOp::Shr,
            ProgramOp::Rotl,
            ProgramOp::Rotr,
            ProgramOp::And,
            ProgramOp::Or,
            ProgramOp::Xor,
        ];

        proptest! {
            #[test]
            fn the_oracle_matches_native_integers(
                op in proptest::sample::select(OPS.to_vec()),
                ty in proptest::sample::select(IntegerType::ALL.to_vec()),
                a in any::<i128>(),
                b in any::<i128>(),
            ) {
                let a = ty.wrap(a);
                let shifts = matches!(op, ProgramOp::Shl | ProgramOp::Shr | ProgramOp::Rotl | ProgramOp::Rotr);
                let b = if shifts { b.rem_euclid(ty.bits() as i128) } else { ty.wrap(b) };
                // The second operand encrypted, or (where allowed) a constant.
                let args = if shifts { vec![Arg::Input(0), Arg::Const(b.to_string())] } else { vec![Arg::Input(0), Arg::Input(1)] };
                let inputs = if shifts { vec![a] } else { vec![a, b] };
                let program = Program { steps: vec![Step { op, args }] };
                let got = program.check(ty, inputs.len()).unwrap().eval_plain(&inputs);
                prop_assert_eq!(got, PlainValue::Int(native(op, ty, a, b)));
            }
        }
    }
}

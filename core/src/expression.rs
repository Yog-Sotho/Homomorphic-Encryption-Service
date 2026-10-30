//! A small expression syntax for programs, e.g. `(a + b) * 3 < c ? a : b`.
//!
//! - Inputs are the letters `a` to `p` (`a` is input 1); numbers are plaintext
//!   constants.
//! - Operators, loosest first: `?:`, `||`, `&&`, comparisons (`== != < <= > >=`),
//!   `|`, `^`, `&`, `<< >>`, `+ -`, `* / %`, then the unary `-` and `!` (also `~`).
//!   `&`, `|`, `^` and `!` are bitwise on integers and logical on booleans;
//!   `&&` and `||` are the same as `&` and `|` with a looser precedence.
//! - Functions: `min(x, y)`, `max(x, y)`, `abs(x)`, `rotl(x, n)`, `rotr(x, n)`.
//!
//! The browser has its own parser (`frontend/src/lib/fhe/program.ts`); both are
//! checked against the cases in `core/tests/program_vectors.json`.

use crate::program::{Arg, Program, ProgramOp, Step};

const MAX_EXPRESSION_LEN: usize = 4096;
const MAX_DEPTH: usize = 64;
const INPUT_NAMES: &str = "abcdefghijklmnop";

/// A compiled expression: the program and how many inputs it reads (one more
/// than the highest letter used).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compiled {
    pub program: Program,
    pub input_count: usize,
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Number(String),
    Name(String),
    Op(&'static str),
}

fn tokenize(text: &str) -> Result<Vec<(usize, Token)>, String> {
    const OPS: [&str; 24] = [
        "<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "+", "-", "*", "/", "%", "&", "|", "^",
        "!", "~", "<", ">", "?", ":", "(", ")",
    ];
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c.is_ascii_digit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            tokens.push((start, Token::Number(chars[start..i].iter().collect())));
        } else if c.is_ascii_alphabetic() {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            tokens.push((start, Token::Name(chars[start..i].iter().collect())));
        } else if c == ',' {
            tokens.push((i, Token::Op(",")));
            i += 1;
        } else {
            let rest: String = chars[i..chars.len().min(i + 2)].iter().collect();
            let op = OPS
                .iter()
                .find(|op| rest.starts_with(**op))
                .ok_or_else(|| format!("Unexpected '{c}' at position {}", i + 1))?;
            tokens.push((i, Token::Op(op)));
            i += op.len();
        }
    }
    Ok(tokens)
}

#[derive(Debug, Clone)]
enum Expr {
    Input(usize),
    Const(i128),
    Neg(Box<Expr>),
    Not(Box<Expr>),
    Binary(&'static str, Box<Expr>, Box<Expr>),
    Ternary(Box<Expr>, Box<Expr>, Box<Expr>),
    Call(String, Vec<Expr>),
}

struct Parser {
    tokens: Vec<(usize, Token)>,
    pos: usize,
    depth: usize,
    text_len: usize,
}

/// Binary operator levels, loosest first.
const LEVELS: [&[&str]; 9] = [
    &["||"],
    &["&&"],
    &["==", "!=", "<", "<=", ">", ">="],
    &["|"],
    &["^"],
    &["&"],
    &["<<", ">>"],
    &["+", "-"],
    &["*", "/", "%"],
];

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos).map(|(_, t)| t)
    }

    fn position(&self) -> usize {
        self.tokens.get(self.pos).map_or(self.text_len, |(p, _)| *p) + 1
    }

    fn eat(&mut self, op: &str) -> bool {
        if matches!(self.peek(), Some(Token::Op(o)) if *o == op) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, op: &str) -> Result<(), String> {
        if self.eat(op) {
            Ok(())
        } else {
            Err(format!("Expected '{op}' at position {}", self.position()))
        }
    }

    fn nest(&mut self) -> Result<(), String> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(format!(
                "The expression nests more than {MAX_DEPTH} levels deep"
            ));
        }
        Ok(())
    }

    fn ternary(&mut self) -> Result<Expr, String> {
        self.nest()?;
        let condition = self.binary(0)?;
        let expr = if self.eat("?") {
            let if_true = self.ternary()?;
            self.expect(":")?;
            let if_false = self.ternary()?;
            Expr::Ternary(Box::new(condition), Box::new(if_true), Box::new(if_false))
        } else {
            condition
        };
        self.depth -= 1;
        Ok(expr)
    }

    fn binary(&mut self, level: usize) -> Result<Expr, String> {
        if level == LEVELS.len() {
            return self.unary();
        }
        let mut left = self.binary(level + 1)?;
        let mut comparisons = 0;
        while let Some(Token::Op(op)) = self.peek() {
            let op: &'static str = op;
            if !LEVELS[level].contains(&op) {
                break;
            }
            if level == 2 {
                comparisons += 1;
                if comparisons > 1 {
                    return Err(format!(
                        "Comparisons cannot be chained (position {}); use && between them",
                        self.position()
                    ));
                }
            }
            self.pos += 1;
            let right = self.binary(level + 1)?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Expr, String> {
        if self.eat("-") {
            self.nest()?;
            let operand = self.unary()?;
            self.depth -= 1;
            return Ok(match operand {
                Expr::Const(c) => Expr::Const(-c),
                other => Expr::Neg(Box::new(other)),
            });
        }
        if self.eat("!") || self.eat("~") {
            self.nest()?;
            let operand = self.unary()?;
            self.depth -= 1;
            return Ok(Expr::Not(Box::new(operand)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, String> {
        let position = self.position();
        match self.tokens.get(self.pos).cloned() {
            Some((_, Token::Number(digits))) => {
                self.pos += 1;
                digits
                    .parse::<i128>()
                    .ok()
                    .filter(|v| *v <= u64::MAX as i128)
                    .map(Expr::Const)
                    .ok_or_else(|| format!("The number at position {position} is too large"))
            }
            Some((_, Token::Name(name))) => {
                self.pos += 1;
                if self.eat("(") {
                    let mut args = Vec::new();
                    if !self.eat(")") {
                        loop {
                            args.push(self.ternary()?);
                            if self.eat(")") {
                                break;
                            }
                            self.expect(",")?;
                        }
                    }
                    return Ok(Expr::Call(name, args));
                }
                match INPUT_NAMES.find(name.as_str()) {
                    Some(index) if name.len() == 1 => Ok(Expr::Input(index)),
                    _ => Err(format!(
                        "Unknown name '{name}' at position {position}: inputs are the letters a to p"
                    )),
                }
            }
            Some((_, Token::Op("("))) => {
                self.pos += 1;
                let expr = self.ternary()?;
                self.expect(")")?;
                Ok(expr)
            }
            Some(_) => Err(format!("Unexpected symbol at position {position}")),
            None => Err("The expression ends too early".to_string()),
        }
    }
}

struct Lowering {
    steps: Vec<Step>,
    input_count: usize,
}

impl Lowering {
    fn emit(&mut self, op: ProgramOp, args: Vec<Arg>) -> Arg {
        self.steps.push(Step { op, args });
        Arg::Step(self.steps.len() - 1)
    }

    fn value(&mut self, expr: &Expr, what: &str) -> Result<Arg, String> {
        match self.lower(expr)? {
            Arg::Const(_) => Err(format!("{what} must be encrypted, not a constant")),
            arg => Ok(arg),
        }
    }

    fn lower(&mut self, expr: &Expr) -> Result<Arg, String> {
        Ok(match expr {
            Expr::Input(i) => {
                self.input_count = self.input_count.max(i + 1);
                Arg::Input(*i)
            }
            Expr::Const(c) => Arg::Const(c.to_string()),
            Expr::Neg(x) => {
                let x = self.value(x, "The operand of -")?;
                self.emit(ProgramOp::Neg, vec![x])
            }
            Expr::Not(x) => {
                let x = self.value(x, "The operand of !")?;
                self.emit(ProgramOp::Not, vec![x])
            }
            Expr::Ternary(c, t, f) => {
                let c = self.value(c, "The condition of ?:")?;
                let t = self.value(t, "Both branches of ?:")?;
                let f = self.value(f, "Both branches of ?:")?;
                self.emit(ProgramOp::Select, vec![c, t, f])
            }
            Expr::Binary(op, a, b) => {
                let (a, b) = (self.lower(a)?, self.lower(b)?);
                self.binary(op, a, b)?
            }
            Expr::Call(name, args) => {
                let lowered = args
                    .iter()
                    .map(|a| self.lower(a))
                    .collect::<Result<Vec<_>, _>>()?;
                let op = match (name.as_str(), lowered.len()) {
                    ("min", 2) => {
                        return self.binary("min", lowered[0].clone(), lowered[1].clone())
                    }
                    ("max", 2) => {
                        return self.binary("max", lowered[0].clone(), lowered[1].clone())
                    }
                    ("abs", 1) => ProgramOp::Abs,
                    ("rotl", 2) => ProgramOp::Rotl,
                    ("rotr", 2) => ProgramOp::Rotr,
                    ("min" | "max" | "rotl" | "rotr", n) => {
                        return Err(format!("{name}() takes 2 arguments, not {n}"))
                    }
                    ("abs", n) => return Err(format!("abs() takes 1 argument, not {n}")),
                    _ => {
                        return Err(format!(
                            "Unknown function {name}(): use min, max, abs, rotl or rotr"
                        ))
                    }
                };
                if matches!(lowered[0], Arg::Const(_)) {
                    return Err(format!("The first argument of {name}() must be encrypted"));
                }
                self.emit(op, lowered)
            }
        })
    }

    /// `a op b`, with a constant on the left moved to the right where the
    /// operation allows it.
    fn binary(&mut self, op: &str, a: Arg, b: Arg) -> Result<Arg, String> {
        let program_op = match op {
            "+" => ProgramOp::Add,
            "-" => ProgramOp::Subtract,
            "*" => ProgramOp::Multiply,
            "/" => ProgramOp::Divide,
            "%" => ProgramOp::Remainder,
            "&" | "&&" => ProgramOp::And,
            "|" | "||" => ProgramOp::Or,
            "^" => ProgramOp::Xor,
            "<<" => ProgramOp::Shl,
            ">>" => ProgramOp::Shr,
            "==" => ProgramOp::Eq,
            "!=" => ProgramOp::Ne,
            "<" => ProgramOp::Lt,
            "<=" => ProgramOp::Le,
            ">" => ProgramOp::Gt,
            ">=" => ProgramOp::Ge,
            "min" => ProgramOp::Min,
            "max" => ProgramOp::Max,
            _ => unreachable!("parser operators"),
        };
        match (&a, &b) {
            (Arg::Const(x), Arg::Const(y)) => fold(op, program_op, x, y).map(Arg::Const),
            (Arg::Const(_), _) => {
                let swapped = match program_op {
                    ProgramOp::Add
                    | ProgramOp::Multiply
                    | ProgramOp::And
                    | ProgramOp::Or
                    | ProgramOp::Xor
                    | ProgramOp::Eq
                    | ProgramOp::Ne
                    | ProgramOp::Min
                    | ProgramOp::Max => Some(program_op),
                    ProgramOp::Lt => Some(ProgramOp::Gt),
                    ProgramOp::Le => Some(ProgramOp::Ge),
                    ProgramOp::Gt => Some(ProgramOp::Lt),
                    ProgramOp::Ge => Some(ProgramOp::Le),
                    _ => None,
                };
                match (swapped, program_op) {
                    (Some(op), _) => Ok(self.emit(op, vec![b, a])),
                    // c - x = (-x) + c
                    (None, ProgramOp::Subtract) => {
                        let negated = self.emit(ProgramOp::Neg, vec![b]);
                        Ok(self.emit(ProgramOp::Add, vec![negated, a]))
                    }
                    _ => Err(format!(
                        "The left side of '{op}' must be encrypted, not a constant"
                    )),
                }
            }
            _ => Ok(self.emit(program_op, vec![a, b])),
        }
    }
}

/// Evaluates an operation on two constants exactly (the type's range is checked
/// later, by [`Program::check`]). Comparisons have no constant result.
fn fold(op: &str, program_op: ProgramOp, x: &str, y: &str) -> Result<String, String> {
    let (x, y): (i128, i128) = (x.parse().unwrap_or_default(), y.parse().unwrap_or_default());
    let shift = || u32::try_from(y).ok().filter(|n| *n < 127);
    let value = match program_op {
        ProgramOp::Add => x.checked_add(y),
        ProgramOp::Subtract => x.checked_sub(y),
        ProgramOp::Multiply => x.checked_mul(y),
        ProgramOp::Divide | ProgramOp::Remainder if y == 0 => {
            return Err("cannot divide by the constant 0".into())
        }
        ProgramOp::Divide => x.checked_div(y),
        ProgramOp::Remainder => x.checked_rem(y),
        ProgramOp::And => Some(x & y),
        ProgramOp::Or => Some(x | y),
        ProgramOp::Xor => Some(x ^ y),
        ProgramOp::Shl => shift().and_then(|n| x.checked_shl(n)),
        ProgramOp::Shr => shift().map(|n| x >> n),
        ProgramOp::Min => Some(x.min(y)),
        ProgramOp::Max => Some(x.max(y)),
        _ => return Err(format!("'{op}' needs at least one encrypted operand")),
    };
    value
        .map(|v| v.to_string())
        .ok_or_else(|| format!("The constant '{x} {op} {y}' is out of range"))
}

/// Compiles an expression into a program. The program still has to pass
/// [`Program::check`] for a type (constants' ranges, operand kinds).
pub fn parse_expression(text: &str) -> Result<Compiled, String> {
    if text.len() > MAX_EXPRESSION_LEN {
        return Err(format!(
            "The expression is longer than {MAX_EXPRESSION_LEN} characters"
        ));
    }
    let tokens = tokenize(text)?;
    let mut parser = Parser {
        tokens,
        pos: 0,
        depth: 0,
        text_len: text.chars().count(),
    };
    let expr = parser.ternary()?;
    if parser.pos != parser.tokens.len() {
        return Err(format!(
            "Unexpected symbol at position {}",
            parser.position()
        ));
    }
    let mut lowering = Lowering {
        steps: Vec::new(),
        input_count: 0,
    };
    match lowering.lower(&expr)? {
        Arg::Const(_) => return Err("The expression must use at least one input (a to p)".into()),
        // A bare input: the identity, as `x + 0`.
        input @ Arg::Input(_) => {
            lowering.emit(ProgramOp::Add, vec![input, Arg::Const("0".into())]);
        }
        Arg::Step(_) => {}
    }
    Ok(Compiled {
        program: Program {
            steps: lowering.steps,
        },
        input_count: lowering.input_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IntegerType, PlainValue};
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Vector {
        expr: String,
        #[serde(rename = "type")]
        integer_type: IntegerType,
        #[serde(default)]
        inputs: Vec<String>,
        result: Option<String>,
        error: Option<String>,
    }

    /// The cases the browser's parser is tested against too.
    #[test]
    fn shared_vectors() {
        let vectors: Vec<Vector> =
            serde_json::from_str(include_str!("../tests/program_vectors.json")).unwrap();
        assert!(vectors.len() > 20);
        for v in vectors {
            let outcome = parse_expression(&v.expr).and_then(|compiled| {
                let checked = compiled
                    .program
                    .check(v.integer_type, compiled.input_count.max(v.inputs.len()))?;
                let inputs: Vec<i128> = v
                    .inputs
                    .iter()
                    .map(|i| v.integer_type.parse_value(i).unwrap())
                    .collect();
                Ok(checked.eval_plain(&inputs))
            });
            match (outcome, &v.result, &v.error) {
                (Ok(value), Some(expected), None) => {
                    let got = match value {
                        PlainValue::Bool(b) => b.to_string(),
                        PlainValue::Int(i) => i.to_string(),
                    };
                    assert_eq!(&got, expected, "{}", v.expr);
                }
                (Err(e), None, Some(expected)) => {
                    assert!(
                        e.contains(expected.as_str()),
                        "{}: {e:?} lacks {expected:?}",
                        v.expr
                    )
                }
                (outcome, ..) => panic!("{}: unexpected {outcome:?}", v.expr),
            }
        }
    }

    #[test]
    fn constants_on_the_left_move_right() {
        let steps = |text: &str| parse_expression(text).unwrap().program.steps;
        assert_eq!(
            steps("3 < a"),
            vec![Step {
                op: ProgramOp::Gt,
                args: vec![Arg::Input(0), Arg::Const("3".into())]
            }]
        );
        assert_eq!(steps("10 - a").len(), 2);
        assert_eq!(parse_expression("a").unwrap().program.steps.len(), 1);
    }

    #[test]
    fn deep_nesting_is_refused_without_overflowing_the_stack() {
        let deep = format!("{}a{}", "(".repeat(5000), ")".repeat(5000));
        assert!(parse_expression(&deep[..4096.min(deep.len())]).is_err());
        let nested = format!("{}a{}", "(".repeat(100), ")".repeat(100));
        assert!(parse_expression(&nested).unwrap_err().contains("nests"));
        assert!(parse_expression(&"-".repeat(200)).is_err());
    }
}

//! Macros for opcode dispatch.

/// Generate a match arm for a binary arithmetic operation.
#[macro_export]
macro_rules! arith_op {
    ($stack:expr, $op:tt) => {{
        let b = $stack.pop_number(crate::data_stack::MAX_SCRIPT_NUM_LEN)?;
        let a = $stack.pop_number(crate::data_stack::MAX_SCRIPT_NUM_LEN)?;
        $stack.push_number(a $op b)?;
    }};
}

/// Generate a match arm for a comparison operation.
#[macro_export]
macro_rules! compare_op {
    ($stack:expr, $op:tt) => {{
        let b = $stack.pop_number(crate::data_stack::MAX_SCRIPT_NUM_LEN)?;
        let a = $stack.pop_number(crate::data_stack::MAX_SCRIPT_NUM_LEN)?;
        $stack.push_bool(a $op b)?;
    }};
}

/// Generate a match arm for a unary numeric operation.
#[macro_export]
macro_rules! unary_op {
    ($stack:expr, $func:expr) => {{
        let a = $stack.pop_number(crate::data_stack::MAX_SCRIPT_NUM_LEN)?;
        $stack.push_number($func(a))?;
    }};
}

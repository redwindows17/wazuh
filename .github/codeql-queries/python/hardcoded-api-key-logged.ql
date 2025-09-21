/**
 * @name Hard-coded API key that may be logged (Python)
 * @description Find when a hard-coded secret-like string (assignment) is used as an argument to print() or logging.* calls.
 * @kind problem
 * @severity error
 * @id py/hardcoded-api-key-logged
 */

import python

int minLen = 20

predicate keyName(string name) {
  name.matches("(?i).*\\b(api[_-]?key|key|token|secret)\\b.*")
}

class HardKeyAssignment {
  Assignment a;
  string varName;
  HardKeyAssignment(Assignment assign, string name) {
    this.a = assign;
    this.varName = name;
  }
}

/**
 * Identify assignments that look like hard-coded keys (same logic as previous ql)
 */
from Assignment assign, Expr lhs, Expr rhs, string name
where
  lhs = assign.getTarget() and
  rhs = assign.getSource() and
  rhs instanceof StringLiteral and
  rhs.getValue().length() > minLen and
  lhs instanceof Name and
  name = (lhs as Name).getIdentifier() and
  keyName(name)
select new HardKeyAssignment(assign, name), "Hard-coded key assigned to '" + name + "'."

 /**
  * Find calls where an argument is the variable assigned above, and the callee is print() or logging.* or logger.* (common logging functions).
  * We look for a CallExpression whose argument is a Name referencing that variable.
  */
from Call call, Expr arg, Name argName, Assignment assign, string name
where
  // locate call arg that is the variable name (simple case)
  arg = call.getArg(0) and
  arg instanceof Name and
  argName = arg as Name and
  // find matching hardcoded assignment
  assign.getTarget() instanceof Name and
  (assign.getTarget() as Name).getIdentifier() = argName.getIdentifier() and
  assign.getSource() instanceof StringLiteral and
  assign.getSource().getValue().length() > minLen and
  keyName(argName.getIdentifier()) and
  // call is either builtin print OR a member access ending with logging / logger / log
  (
    call.getCallee().toString() = "print" or
    call.getCallee().toString().matches("(?i).*logging\\..*") or
    call.getCallee().toString().matches("(?i).*logger\\..*")
  )
select call, "Hard-coded key '" + argName.getIdentifier() + "' is being passed to a logging/print call — this may leak secrets."

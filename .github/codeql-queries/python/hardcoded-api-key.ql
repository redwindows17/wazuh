/**
 * @name Hard-coded API key (Python)
 * @description Find assignments of long string literals to variables whose name looks like an API key or secret.
 * @kind problem
 * @severity error
 * @id py/hardcoded-api-key
 */

import python

/**
 We consider hardcoded keys as:
  - assignment to a name containing "key", "token", or "secret" (case-insensitive)
  - right-hand side is a string literal longer than minLen
*/
int minLen = 20

predicate keyName(string name) {
  name.matches("(?i).*\\b(api[_-]?key|key|token|secret)\\b.*")
}

from Assignment assign, Expr lhs, Expr rhs, string varName
where
  // assignment like NAME = "..." (single target)
  lhs = assign.getTarget() and
  rhs = assign.getSource() and
  // ensure RHS is a string literal and long enough
  rhs instanceof StringLiteral and
  rhs.getValue().length() > minLen and
  // get variable name (if simple name)
  (
    lhs instanceof Name and
    varName = (lhs as Name).getIdentifier()
  ) and
  keyName(varName)
select assign, "Hard-coded secret-like string assigned to variable '" + varName + "'. Avoid committing secrets; load from environment / secret store."

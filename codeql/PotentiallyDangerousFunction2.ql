/**
 * @name Use of potentially dangerous function
 * @description Certain standard library functions are dangerous to call..
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/potentially-dangerous-function2
 * @tags reliability
 *       security
 *
 * Borrowed from
 * https://github.com/Semmle/ql/blob/master/cpp/ql/src/Security/CWE/CWE-676/PotentiallyDangerousFunction.ql
 */

import cpp

predicate potentiallyDangerousFunction(Function f, string message) {
    exists(string name | f.hasGlobalName(name) |
    (
        name = "strcpy" or
        name = "strncpy" or
        name = "strcat" or
        name = "sprintf"
    )
        and message = "Call to " + name + " is potentially dangerous"
    )
}

from FunctionCall call, Function target, string message
where
call.getTarget() = target and
potentiallyDangerousFunction(target, message)
select call, message

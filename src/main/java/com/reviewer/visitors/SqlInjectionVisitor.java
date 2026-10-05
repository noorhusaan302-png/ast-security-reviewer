package com.reviewer.visitors;

import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.reviewer.model.Finding;

import java.util.List;
import java.util.Set;

public class SqlInjectionVisitor extends VoidVisitorAdapter<List<Finding>> {

    private static final Set<String> SQL_METHODS = Set.of(
        "executeQuery", "executeUpdate", "execute"
    );

    @Override
    public void visit(MethodCallExpr methodCall, List<Finding> findings) {
        super.visit(methodCall, findings);

        String methodName = methodCall.getNameAsString();

        if (SQL_METHODS.contains(methodName)) {
            // Check if any argument is a binary expression using '+' (string concatenation)
            boolean hasConcatenation = methodCall.getArguments().stream()
                .anyMatch(arg -> arg instanceof BinaryExpr binary && 
                                 binary.getOperator() == BinaryExpr.Operator.PLUS);

            if (hasConcatenation) {
                int line = methodCall.getBegin().map(pos -> pos.line).orElse(-1);
                findings.add(new Finding(
                    "SQL_INJECTION_RISK",
                    "CRITICAL",
                    line,
                    "Dynamic SQL query constructed via string concatenation. Use PreparedStatement instead.",
                    methodCall.toString()
                ));
            }
        }
    }
}

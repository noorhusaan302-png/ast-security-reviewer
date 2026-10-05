package com.reviewer.visitors;

import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.reviewer.model.Finding;

import java.util.List;
import java.util.Set;

public class HardcodedSecretVisitor extends VoidVisitorAdapter<List<Finding>> {

    private static final Set<String> SUSPICIOUS_NAMES = Set.of(
        "password", "passwd", "secret", "apikey", "api_key", "token", "auth_token"
    );

    @Override
    public void visit(VariableDeclarator declarator, List<Finding> findings) {
        super.visit(declarator, findings);

        String varName = declarator.getNameAsString().toLowerCase();

        boolean isSuspiciousName = SUSPICIOUS_NAMES.stream().anyMatch(varName::contains);

        if (isSuspiciousName && declarator.getInitializer().isPresent()) {
            if (declarator.getInitializer().get() instanceof StringLiteralExpr) {
                int line = declarator.getBegin().map(pos -> pos.line).orElse(-1);
                findings.add(new Finding(
                    "HARDCODED_SECRET",
                    "CRITICAL",
                    line,
                    "Possible hardcoded credential detected in variable '" + declarator.getNameAsString() + "'",
                    declarator.toString()
                ));
            }
        }
    }
}

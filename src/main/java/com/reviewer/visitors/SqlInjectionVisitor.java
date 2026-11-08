package com.reviewer.visitors;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.reviewer.model.Finding;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Flags JDBC calls (execute, executeQuery, executeUpdate) where the SQL string is built
 * from non-constant pieces: '+' concatenation, String.format(...), a StringBuilder,
 * or a local variable built one of those ways.
 * Queries made only of string literals, and PreparedStatement calls with no
 * arguments, are not flagged.
 */
public class SqlInjectionVisitor extends VoidVisitorAdapter<List<Finding>> {

    private static final Set<String> SQL_METHODS = Set.of(
        "executeQuery", "executeUpdate", "execute"
    );

    @Override
    public void visit(MethodCallExpr methodCall, List<Finding> findings) {
        super.visit(methodCall, findings);

        if (!SQL_METHODS.contains(methodCall.getNameAsString())) return;
        if (methodCall.getArguments().isEmpty()) return; // preparedStatement.executeQuery()

        Expression sqlArg = methodCall.getArgument(0);
        if (isDynamic(sqlArg, methodCall, 0)) {
            int line = methodCall.getBegin().map(pos -> pos.line).orElse(-1);
            findings.add(new Finding(
                "SQL_INJECTION_RISK",
                "CRITICAL",
                line,
                "Dynamic SQL query built from non-constant input. Use PreparedStatement with ? parameters instead.",
                methodCall.toString()
            ));
        }
    }

    /** True if the expression builds SQL from something other than string literals. */
    private boolean isDynamic(Expression expr, Node context, int depth) {
        if (depth > 5) return false; // stop on long variable chains

        if (expr.isEnclosedExpr()) {
            return isDynamic(expr.asEnclosedExpr().getInner(), context, depth + 1);
        }

        // "SELECT ... '" + userInput + "'"
        if (expr instanceof BinaryExpr binary && binary.getOperator() == BinaryExpr.Operator.PLUS) {
            return !isConstant(binary);
        }

        if (expr instanceof MethodCallExpr call) {
            // String.format("... %s", userInput)
            if (call.getNameAsString().equals("format") && call.getArguments().size() > 1) {
                return true;
            }
            // sb.toString() where sb is a StringBuilder declared in this method
            if (call.getNameAsString().equals("toString") && call.getScope().isPresent()
                    && call.getScope().get() instanceof NameExpr scopeName) {
                return findLocal(scopeName.getNameAsString(), context)
                    .map(v -> v.getTypeAsString().equals("StringBuilder")
                              || v.getTypeAsString().equals("StringBuffer"))
                    .orElse(false);
            }
        }

        // String query = "..." + userInput;  stmt.executeQuery(query);
        if (expr instanceof NameExpr name) {
            Optional<VariableDeclarator> decl = findLocal(name.getNameAsString(), context);
            if (decl.isPresent() && decl.get().getInitializer().isPresent()
                    && isDynamic(decl.get().getInitializer().get(), context, depth + 1)) {
                return true;
            }
            // query += userInput;  later in the same method
            return findEnclosingMethod(context).map(m -> m.findAll(AssignExpr.class).stream()
                .anyMatch(a -> a.getTarget().toString().equals(name.getNameAsString())
                    && (a.getOperator() == AssignExpr.Operator.PLUS
                        || isDynamic(a.getValue(), context, depth + 1))))
                .orElse(false);
        }

        return false;
    }

    private boolean isConstant(Expression expr) {
        if (expr.isStringLiteralExpr() || expr.isIntegerLiteralExpr() || expr.isCharLiteralExpr()) return true;
        if (expr instanceof BinaryExpr b && b.getOperator() == BinaryExpr.Operator.PLUS) {
            return isConstant(b.getLeft()) && isConstant(b.getRight());
        }
        if (expr.isEnclosedExpr()) return isConstant(expr.asEnclosedExpr().getInner());
        return false;
    }

    private Optional<MethodDeclaration> findEnclosingMethod(Node node) {
        return node.findAncestor(MethodDeclaration.class);
    }

    private Optional<VariableDeclarator> findLocal(String varName, Node context) {
        return findEnclosingMethod(context).flatMap(m -> m.findAll(VariableDeclarator.class).stream()
            .filter(v -> v.getNameAsString().equals(varName))
            .findFirst());
    }
}

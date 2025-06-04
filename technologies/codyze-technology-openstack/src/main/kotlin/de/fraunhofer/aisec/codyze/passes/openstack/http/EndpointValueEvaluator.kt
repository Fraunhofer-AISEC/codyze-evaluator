/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.openstack.passes.http

import de.fraunhofer.aisec.cpg.evaluation.ValueEvaluator
import de.fraunhofer.aisec.cpg.graph.HasOperatorCode
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.declarations.ParameterDeclaration
import de.fraunhofer.aisec.cpg.graph.declarations.VariableDeclaration
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.ConditionalExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.InitializerListExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Reference

/**
 * The [ValueEvaluator] resolves values by following the DFG edges to literals. The
 * [EndpointValueEvaluator] extends this functionality to manipulate API endpoints, e.g., replacing
 * "%s" with "{param_name}".
 */
class EndpointValueEvaluator : ValueEvaluator() {
    override fun computeBinaryOpEffect(
        lhsValue: Any?,
        rhsValue: Any?,
        has: HasOperatorCode?,
    ): Any? {
        val lhs =
            when (lhsValue) {
                is String -> lhsValue
                is LinkedHashSet<*> -> lhsValue.firstOrNull() as? String
                else -> null
            }

        val rhs = rhsValue as? List<*>
        if (has?.operatorCode == "%") {
            if (lhs is String && rhs != null) {
                var result = lhs
                rhs.forEach { value -> result = result?.replaceFirst("%s", "{${value}}") }
                return result
            } else {
                return lhs?.replace("%s", if (rhsValue == "") "$rhsValue" else "{$rhsValue}")
            }
        } else {
            return lhs?.replace("%s", if (rhsValue == "") "$rhsValue" else "{$rhsValue}")
        }
    }

    override fun evaluateInternal(node: Node?, depth: Int): Any? {
        return when (node) {
            is CallExpression -> {
                when (node.name.localName) {
                    "build_query_param" -> ""
                    "_build_list_url" ->
                        node.arguments.firstOrNull()?.let { super.evaluateInternal(it, depth) }
                            ?: ""

                    "_build_url" ->
                        node.arguments.firstOrNull()?.let { super.evaluateInternal(node, depth) }
                            ?: ""

                    else -> {
                        node.arguments.firstOrNull()?.let {
                            if (it is Reference) return it.name.localName
                        }
                        super.evaluateInternal(node, depth)
                    }
                }
            }

            is ParameterDeclaration ->
                node.default?.let { super.evaluateInternal(it, depth) } ?: node.name.localName

            is MemberExpression -> {
                if (node.name.localName == "base_url") {
                    // Take FieldDeclaration
                    return super.evaluateInternal(node.refersTo, depth)
                }
                return super.evaluateInternal(node, depth)
            }

            is ConditionalExpression -> {
                if (node.condition.name.localName == "url_path") {
                    return ""
                }
                return super.evaluateInternal(node, depth)
            }

            is VariableDeclaration -> {
                if (node.name.localName == "base_url") {
                    return super.evaluateInternal(node, depth)
                }
                return super.evaluateInternal(node, depth)
            }

            is InitializerListExpression -> {
                return node.initializers.mapNotNull { super.evaluateInternal(it, depth) }
            }

            else -> super.evaluateInternal(node, depth)
        }
    }
}

/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.openstack.passes.auth

import de.fraunhofer.aisec.codyze.concepts.auth.Policy
import de.fraunhofer.aisec.codyze.concepts.auth.newAuthorization
import de.fraunhofer.aisec.codyze.concepts.auth.newAuthorize
import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.graph.Backward
import de.fraunhofer.aisec.cpg.graph.Component
import de.fraunhofer.aisec.cpg.graph.GraphToFollow
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.allChildrenWithOverlays
import de.fraunhofer.aisec.cpg.graph.calls
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.declarations.FieldDeclaration
import de.fraunhofer.aisec.cpg.graph.declarations.MethodDeclaration
import de.fraunhofer.aisec.cpg.graph.declarations.VariableDeclaration
import de.fraunhofer.aisec.cpg.graph.firstParentOrNull
import de.fraunhofer.aisec.cpg.graph.followDFGEdgesUntilHit
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.ConstructExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.KeyValueExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberCallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Reference
import de.fraunhofer.aisec.cpg.passes.ComponentPass

/**
 * A pass that processes registered policies to identify and attach authorization requirements. If
 * an authorization is required within an `HttpEndpoint`, it creates and connects the corresponding
 * authorization concepts and operations.
 */
class AuthorizationPass(ctx: TranslationContext) : ComponentPass(ctx) {
    override fun accept(t: Component) {
        val policies = t.conceptNodes.filterIsInstance<Policy>()
        if (policies.isEmpty()) {
            log.warn("Could not find any policy concept")
            return
        }
        handlePolicies(policies = policies, component = t)
    }

    /** For each `Policy`, finds its associated authorize calls. */
    private fun handlePolicies(policies: List<Policy>, component: Component) {
        policies.forEach { policy ->
            val policyArg = (policy.underlyingNode as? ConstructExpression)?.arguments?.getOrNull(0)
            when (policyArg) {
                is Reference -> {
                    val nameVariable = policyArg.refersTo as? VariableDeclaration ?: return@forEach
                    // We want to find the `context.authorize` calls which check against this
                    // policy
                    // So we go through the usages of the variable and lookup the astParent's
                    // whether they are member calls
                    val authorizeCalls =
                        nameVariable.usages.mapNotNull { usage ->
                            val call = usage.astParent as? MemberCallExpression
                            if (
                                call?.name?.localName == "authorize" &&
                                    call.code?.startsWith("context") == true
                            )
                                call
                            else null
                        }
                    authorizeCalls.forEach { authorizeCall ->
                        applyAuthorization(policy = policy, call = authorizeCall)
                    }
                }
            }
        }
    }

    private fun applyAuthorization(policy: Policy, call: MemberCallExpression) {
        val authorize = call.invokes.firstOrNull() as? MethodDeclaration ?: return
        val policyRef = call.arguments.getOrNull(0) ?: return
        val policyAuthorize =
            authorize.calls.singleOrNull {
                it.name.localName == "authorize" && it.name.parent?.localName == "policy"
            } ?: return

        val action = policyAuthorize.arguments.getOrNull(1) ?: return
        val targets = extractTargets(policyAuthorize) ?: return
        val exception =
            policyAuthorize.arguments.getOrNull(4)
                ?: policyAuthorize.argumentEdges.singleOrNull { it.name == "exc" }?.end
                ?: return
        val authorization =
            newAuthorization(underlyingNode = call, policy = policy, connect = true).also {
                policy.policyRef = policyRef
            }
        newAuthorize(
            underlyingNode = policyAuthorize,
            concept = authorization,
            action = action,
            targets = targets,
            exception = exception,
            connect = true,
        )

        // We need to find out if `authorize` is called in a method which belongs to
        // an HTTPEndpoint
        val method = call.astParent?.firstParentOrNull<MethodDeclaration>()
        if (method != null) {
            val httpEndpoint = method.allChildrenWithOverlays<HttpEndpoint>().singleOrNull()
            httpEndpoint?.authorization = authorization
        }
    }

    /**
     * Extracts the target fields `user_id` and `project_id` from the second argument of the call
     * `policy.authorize(..)`.
     */
    private fun extractTargets(policyAuthorize: CallExpression): Set<Node>? {
        val targetArg = policyAuthorize.arguments.getOrNull(2) ?: return null
        val paths =
            targetArg.followDFGEdgesUntilHit(
                collectFailedPaths = false,
                direction = Backward(GraphToFollow.DFG),
            ) {
                it is KeyValueExpression
            }

        val targets = mutableSetOf<Node>()
        paths.fulfilled.forEach { path ->
            val keyValue = path.nodes.lastOrNull() as? KeyValueExpression ?: return@forEach
            val memberExpr = keyValue.value as? MemberExpression ?: return@forEach
            val field = memberExpr.refersTo as? FieldDeclaration ?: return@forEach

            when (memberExpr.name.localName) {
                "project_id",
                "user_id" -> targets.add(field)
            }
        }
        return targets
    }

    override fun cleanup() {
        // nothing to do
    }
}

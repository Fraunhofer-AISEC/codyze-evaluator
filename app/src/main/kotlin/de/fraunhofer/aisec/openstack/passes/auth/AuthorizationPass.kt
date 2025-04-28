/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.passes.auth

import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.allChildrenWithOverlays
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.declarations.MethodDeclaration
import de.fraunhofer.aisec.cpg.graph.declarations.VariableDeclaration
import de.fraunhofer.aisec.cpg.graph.firstParentOrNull
import de.fraunhofer.aisec.cpg.graph.statements.expressions.ConstructExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberCallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Reference
import de.fraunhofer.aisec.cpg.passes.SymbolResolver
import de.fraunhofer.aisec.cpg.passes.TranslationResultPass
import de.fraunhofer.aisec.cpg.passes.configuration.DependsOn
import de.fraunhofer.aisec.openstack.concepts.auth.Policy
import de.fraunhofer.aisec.openstack.concepts.auth.newAuthorization
import de.fraunhofer.aisec.openstack.passes.http.HttpPecanLibPass
import de.fraunhofer.aisec.openstack.passes.http.HttpWsgiPass

@DependsOn(SymbolResolver::class)
@DependsOn(HttpPecanLibPass::class)
@DependsOn(HttpWsgiPass::class)
@DependsOn(OsloPolicyPass::class)
class AuthorizationPass(ctx: TranslationContext) : TranslationResultPass(ctx) {
    override fun cleanup() {
        // nothing to do
    }

    override fun accept(p0: TranslationResult) {
        val policies = p0.conceptNodes.filterIsInstance<Policy>()
        if (policies.isEmpty()) return

        handlePolicies(policies = policies)
    }

    private fun handlePolicies(policies: List<Policy>) {
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
                            if (call?.name?.localName == "authorize") call else null
                        }
                    authorizeCalls.forEach { authorizeCall ->
                        applyAuthorization(policy = policy, call = authorizeCall)
                    }
                }
            }
        }
    }

    private fun applyAuthorization(policy: Policy, call: MemberCallExpression) {
        val authorization = newAuthorization(underlyingNode = call, policy = policy, connect = true)
        // We need to find out if `authorize` is called in a method which belongs to
        // an HTTPEndpoint
        val method = call.astParent?.firstParentOrNull<MethodDeclaration>()
        if (method != null) {
            val httpEndpoint = method.allChildrenWithOverlays<HttpEndpoint>().singleOrNull()
            // httpEndpoint.authorization += authorization
        }
    }
}

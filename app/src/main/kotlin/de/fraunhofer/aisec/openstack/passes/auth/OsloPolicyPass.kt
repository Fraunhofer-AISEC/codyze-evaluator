/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.passes.auth

import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.graph.Backward
import de.fraunhofer.aisec.cpg.graph.Component
import de.fraunhofer.aisec.cpg.graph.GraphToFollow
import de.fraunhofer.aisec.cpg.graph.Name
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import de.fraunhofer.aisec.cpg.graph.concepts.policy.Policy
import de.fraunhofer.aisec.cpg.graph.concepts.policy.newPolicy
import de.fraunhofer.aisec.cpg.graph.followDFGEdgesUntilHit
import de.fraunhofer.aisec.cpg.graph.mcalls
import de.fraunhofer.aisec.cpg.graph.statements.expressions.InitializerListExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberCallExpression
import de.fraunhofer.aisec.cpg.passes.ComponentPass
import de.fraunhofer.aisec.cpg.passes.configuration.ExecuteLate

// @DependsOn(SymbolResolver::class)
@ExecuteLate
class OsloPolicyPass(ctx: TranslationContext) : ComponentPass(ctx) {
    override fun cleanup() {
        // Nothing to do
    }

    override fun accept(p0: Component) {
        val registerDefaults = p0.mcalls.singleOrNull { it.name.localName == "register_defaults" }

        if (registerDefaults != null) {
            handleRegisterDefaultRules(registerDefaults)
            val policies = p0.conceptNodes.filterIsInstance<Policy>()
        }
    }

    private fun handleRegisterDefaultRules(registerDefaults: MemberCallExpression) {
        val paths =
            registerDefaults.followDFGEdgesUntilHit(direction = Backward(GraphToFollow.DFG)) {
                it is InitializerListExpression
            }
        val full =
            paths.fulfilled.mapNotNull {
                val last = it.lastOrNull()
                if (last != null) {
                    newPolicy(underlyingNode = last, connect = true).also {
                        it.name = Name(last.name.localName)
                    }
                }
            }
    }
}

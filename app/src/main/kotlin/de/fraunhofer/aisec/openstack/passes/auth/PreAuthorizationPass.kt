/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.passes.auth

import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.Component
import de.fraunhofer.aisec.cpg.graph.statements
import de.fraunhofer.aisec.cpg.graph.statements.expressions.SubscriptExpression
import de.fraunhofer.aisec.cpg.passes.ComponentPass
import de.fraunhofer.aisec.cpg.passes.SymbolResolver
import de.fraunhofer.aisec.cpg.passes.configuration.ExecuteBefore
import de.fraunhofer.aisec.cpg.passes.markDirty

@ExecuteBefore(AuthorizationPass::class)
class PreAuthorizationPass(ctx: TranslationContext) : ComponentPass(ctx) {
    override fun accept(t: Component) {
        val reqContext = t.records["RequestContext"]
        if (reqContext == null) {
            log.warn("No 'RequestContext' found in component: ${t.name}")
            return
        }
        t.statements
            .filterIsInstance<SubscriptExpression>()
            .filter { it.code == "req.environ['cinder.context']" }
            .forEach { it.assignedTypes += reqContext.toType() }
        reqContext.markDirty<SymbolResolver>()
    }

    override fun cleanup() {
        // Nothing to do
    }
}

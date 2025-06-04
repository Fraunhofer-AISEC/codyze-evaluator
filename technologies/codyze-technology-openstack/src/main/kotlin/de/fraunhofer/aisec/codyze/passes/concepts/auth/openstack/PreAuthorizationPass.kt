/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.passes.concepts.auth.openstack

import de.fraunhofer.aisec.codyze.technology.openstack.Cinder
import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.statements.expressions.SubscriptExpression
import de.fraunhofer.aisec.cpg.passes.*
import de.fraunhofer.aisec.cpg.passes.configuration.ExecuteBefore

/**
 * A preprocessing pass for [Cinder] that assigns the type to subscript expressions accessing the
 * request context, specifically `req.environ['cinder.context']`, before the [AuthorizationPass] is
 * executed.
 */
@ExecuteBefore(SymbolResolver::class)
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
    }

    override fun cleanup() {
        // Nothing to do
    }
}

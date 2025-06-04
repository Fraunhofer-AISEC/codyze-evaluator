/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.passes.concepts.auth.openstack

import de.fraunhofer.aisec.codyze.profiles.openstack.OsloPolicy
import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.passes.*
import de.fraunhofer.aisec.cpg.passes.configuration.*

/**
 * A necessary pre-step to set a type for the oslo policy enforcer in the OpenStack library
 * [OsloPolicy].
 */
@DependsOn(PythonAddDeclarationsPass::class)
@ExecuteBefore(SymbolResolver::class)
@ExecuteBefore(AuthorizationPass::class)
class SetOsloPolicyEnforcerTypePass(ctx: TranslationContext) : ComponentPass(ctx) {
    override fun accept(t: Component) {
        val policyEnforcer = t.records["Enforcer"]
        if (policyEnforcer == null) {
            log.warn("No 'policy.Enforcer' found in component: ${t.name}")
            return
        }
        val policyEnforcerRef = t.astParent.variables.filter { it.name.localName == "_ENFORCER" }
        if (policyEnforcerRef.isEmpty()) {
            log.warn("No 'policy.Enforcer' found in component: ${t.name}")
            return
        }
        policyEnforcerRef.forEach { it.assignedTypes += policyEnforcer.toType() }
    }

    override fun cleanup() {
        // Nothing to do
    }
}

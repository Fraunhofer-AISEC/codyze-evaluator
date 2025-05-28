/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.passes.auth

import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.Component
import de.fraunhofer.aisec.cpg.graph.get
import de.fraunhofer.aisec.cpg.graph.records
import de.fraunhofer.aisec.cpg.passes.ComponentPass
import de.fraunhofer.aisec.cpg.passes.PythonAddDeclarationsPass
import de.fraunhofer.aisec.cpg.passes.SymbolResolver
import de.fraunhofer.aisec.cpg.passes.configuration.DependsOn
import de.fraunhofer.aisec.cpg.passes.configuration.ExecuteBefore

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

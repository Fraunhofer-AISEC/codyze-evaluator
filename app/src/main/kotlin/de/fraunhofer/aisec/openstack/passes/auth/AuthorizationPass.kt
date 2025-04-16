/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.passes.auth

import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.passes.SymbolResolver
import de.fraunhofer.aisec.cpg.passes.TranslationResultPass
import de.fraunhofer.aisec.cpg.passes.configuration.DependsOn
import de.fraunhofer.aisec.openstack.passes.http.HttpPecanLibPass
import de.fraunhofer.aisec.openstack.passes.http.HttpWsgiPass

@DependsOn(SymbolResolver::class)
@DependsOn(HttpPecanLibPass::class)
@DependsOn(HttpWsgiPass::class)
class AuthorizationPass(ctx: TranslationContext) : TranslationResultPass(ctx) {
    override fun cleanup() {
        // nothing to do
    }

    override fun accept(p0: TranslationResult) {
        val test = p0.conceptNodes.filterIsInstance<HttpEndpoint>()
    }
}

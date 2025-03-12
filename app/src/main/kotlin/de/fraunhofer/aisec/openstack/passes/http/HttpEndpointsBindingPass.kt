/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.passes.http

import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.graph.Component
import de.fraunhofer.aisec.cpg.passes.ComponentPass
import de.fraunhofer.aisec.cpg.passes.SymbolResolver
import de.fraunhofer.aisec.cpg.passes.configuration.DependsOn

@DependsOn(SymbolResolver::class)
@DependsOn(HttpPecanLibPass::class)
class HttpEndpointsBindingPass(ctx: TranslationContext) : ComponentPass(ctx) {

    override fun cleanup() {
        //
    }

    override fun accept(component: Component) {}

    private fun compareApiEndpoints(apiEndpoint1: String, apiEndpoint2: String): Boolean {
        // Return true if the endpoints are exactly the same
        if (apiEndpoint1 == apiEndpoint2) return true

        // Compares two API endpoints by ignoring the content of the parameters (e.g., {any_id})
        // and checking their structure.
        return apiEndpoint1.split(Regex("\\{[^/]+}")) == apiEndpoint2.split(Regex("\\{[^/]+}"))
    }
}

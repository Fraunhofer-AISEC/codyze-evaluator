/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.queries.encryption

import de.fraunhofer.aisec.codyze.technology.openstack.OpenStackComponents
import de.fraunhofer.aisec.cpg.graph.Component
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.file.WriteFile
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpMethod
import de.fraunhofer.aisec.cpg.graph.concepts.logging.LogWrite
import de.fraunhofer.aisec.cpg.graph.firstParentOrNull
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression

/**
 * A list of whitelisted [HttpEndpoint]s that are considered secure key providers.
 *
 * These endpoints are allowed receive secret material without it being a leak.
 */
val secretsWhitelist =
    listOf(
        "barbican.api.controllers.secrets.SecretController.payload.HttpEndpoint",
        "barbican.api.controllers.secrets.SecretController.on_get.HttpEndpoint",
    )

/**
 * These functions are considered leaks of sensitive data outside the component, if secrets are
 * written with them.
 */
val leakingFunctions = listOf("write", "println", "execute", "log")

/**
 * This [Kotlin extension function](https://kotlinlang.org/docs/extensions.html#extension-functions)
 * checks if the [HttpEndpoint] is invoked on is considered a secure key provider.
 *
 * The following http endpoints are considered as a secure key provider:
 * * GET /v1/secrets/{encryption_key_id}/payload in the `Component` "Barbican"
 *
 * @return `true` if the [HttpEndpoint] is a secure key provider, `false` otherwise
 */
fun HttpEndpoint.isSecureOpenStackKeyProvider(): Boolean {
    return httpMethod == HttpMethod.GET &&
        path == "/v1/secrets/{secret_id}/payload" &&
        this.underlyingNode?.firstParentOrNull<Component> {
            it.name.localName == OpenStackComponents.BARBICAN
        } != null
}

/**
 * This [Kotlin extension function](https://kotlinlang.org/docs/extensions.html#extension-functions)
 * checks if the [Node] it is invoked on may be used to leak sensitive data outside the component by
 * considering the following channels:
 * - Writing to a file
 * - Writing to a log
 * - Printing to the console (via a call expression `println`)
 * - Executing a command (via a call expression `execute`)
 * - Being exposed via an Http endpoint which is not explicitly whitelisted by being a "secure key
 *   provider"
 *
 * @return `true` if this [Node] can be used to leak data.
 */
fun Node.dataLeavesOpenStackComponent(): Boolean {
    return this is WriteFile ||
        this is LogWrite ||
        ((this is CallExpression) && (this.name.localName in leakingFunctions)) ||
        (this is HttpEndpoint && this.name.toString() !in secretsWhitelist)
}

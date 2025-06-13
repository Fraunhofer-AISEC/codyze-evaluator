/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.queries.authentication

import de.fraunhofer.aisec.codyze.profiles.openstack.Barbican
import de.fraunhofer.aisec.codyze.profiles.openstack.Cinder
import de.fraunhofer.aisec.cpg.graph.component
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint

/**
 * The list of valid token providers that are valid for the project.
 *
 * Note: This set may change depending on the project or state-of-the-art.
 */
val tokenProvider = setOf("fernet", "jws")

/**
 * This [Kotlin extension function](https://kotlinlang.org/docs/extensions.html#extension-functions)
 * checks if the [HttpEndpoint] it is invoked on either has cinder as underlyingNode with the path
 * "/v3" or barbican with the path "/v1".
 *
 * @return `true` if this [HttpEndpoint] should have authentication.
 */
fun HttpEndpoint.isCurrentBarbicanOrCinderAPI(): Boolean {
    return (this.underlyingNode?.component?.name?.localName == Cinder.name &&
        this.path.startsWith("/v3/")) ||
        (this.underlyingNode?.component?.name?.localName == Barbican.name &&
            this.path.startsWith("/v1/"))
}

/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.queries.authentication

import de.fraunhofer.aisec.codyze.profiles.openstack.Keystone
import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationOptionSource
import de.fraunhofer.aisec.cpg.graph.evaluate
import de.fraunhofer.aisec.cpg.query.QueryOperators
import de.fraunhofer.aisec.cpg.query.QueryTree
import de.fraunhofer.aisec.cpg.query.allExtended

/**
 * This query checks if the analyzed OpenStack environment is configured to use [Keystone] for
 * authentication.
 */
context(TranslationResult)
fun useKeystoneForAuthentication(): QueryTree<Boolean> {
    val tr = this@TranslationResult
    return tr.allExtended<ConfigurationOptionSource>(
        sel = { it.name.localName == "auth_strategy" },
        mustSatisfy = {
            QueryTree(
                value = it.evaluate().toString() == Keystone.name,
                stringRepresentation = "Component config: ${it.location?.artifactLocation}",
                operator = QueryOperators.EVALUATE,
            )
        },
    )
}

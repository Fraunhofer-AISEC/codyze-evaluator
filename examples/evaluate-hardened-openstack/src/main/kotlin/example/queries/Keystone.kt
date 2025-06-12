/*
 * This file is part of the OpenStack Checker
 */
package example.queries

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationOptionSource
import de.fraunhofer.aisec.cpg.query.*

/**
 * Checks if the [TranslationResult] contains a [ConfigurationOptionSource] that configures that the
 * authentication strategy is set to "keystone".
 */
context(TranslationResult)
fun keystoneAuthStrategyConfigured(): QueryTree<Boolean> {
    val tr = this@TranslationResult
    return tr.allExtended<ConfigurationOptionSource>(
        sel = { it.name.localName == "auth_strategy" },
        mustSatisfy = {
            QueryTree(
                value = it.evaluate().toString() == "keystone",
                stringRepresentation = "Component config: ${it.location?.artifactLocation}",
                operator = QueryOperators.EVALUATE,
            )
        },
    )
}

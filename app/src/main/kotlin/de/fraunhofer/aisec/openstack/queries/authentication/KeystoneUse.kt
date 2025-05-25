/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.queries.authentication

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationOptionSource
import de.fraunhofer.aisec.cpg.graph.evaluate
import de.fraunhofer.aisec.cpg.query.QueryTree
import de.fraunhofer.aisec.cpg.query.allExtended

// Todo Proper Dokumentation
fun useKeystoneForAuthentication(tr: TranslationResult): QueryTree<Boolean> {
    return tr.allExtended<ConfigurationOptionSource>(
        sel = { it.name.localName == "auth_strategy" },
        mustSatisfy = {
            QueryTree<Boolean>(
                value = it.evaluate().toString() == "keystone",
                stringRepresentation = "Component config: ${it.location?.artifactLocation}",
            )
        },
    )
}

/*
 * This file is part of the OpenStack Checker
 */
package example.queries

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.query.QueryTree

fun verySpecificQuery(tr: TranslationResult): QueryTree<Boolean> {
    return QueryTree(true)
}

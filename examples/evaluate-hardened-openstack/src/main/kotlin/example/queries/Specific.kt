/*
 * This file is part of the OpenStack Checker
 */
package example.queries

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.query.QueryTree
import de.fraunhofer.aisec.cpg.query.toQueryTree

context(TranslationResult)
fun verySpecificQuery(): QueryTree<Boolean> {
    val tr = this@TranslationResult
    return true.toQueryTree()
}

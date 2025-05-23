/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.queries.encryption

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.DiskEncryption
import de.fraunhofer.aisec.cpg.query.*


/**
 * This query enforces the following statement: "Given a block device encryption E, if an encryption
 * algorithm A is employed, then A must be a state-of-the-art cryptographic algorithm (e.g., BSI
 * TR-02102-1)"
 *
 * Note that BSI TR-02102-1 only mentions aes-xts as having "relatively good security properties and
 * efficiency"
 */
fun stateOfTheArtEncryption(tr: TranslationResult): QueryTree<Boolean> {
    // We currently allow the two ciphers aes-xts-plain64 and aes-cbc-essiv.
    // This could be extracted to a variable outside this statement.
    val allowedCiphers = listOf("aes-xts-plain64", "aes-cbc-essiv")

    // The predicate must hold for all DiskEncryption concepts.
    return tr.allExtended<DiskEncryption> {
        // The cipher's name must be in the list of allowed ciphers.
        // We use the Query-API's infix function `IN` for the check.
        // Since this function requires a QueryTree object as input,
        // we use manually create one based on the cipher's name.
        QueryTree(it.cipher?.cipherName) IN allowedCiphers
    }
}

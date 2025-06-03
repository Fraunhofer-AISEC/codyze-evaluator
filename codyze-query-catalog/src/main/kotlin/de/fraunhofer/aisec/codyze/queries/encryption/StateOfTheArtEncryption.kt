/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.queries.encryption

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.DiskEncryption
import de.fraunhofer.aisec.cpg.query.IN
import de.fraunhofer.aisec.cpg.query.QueryTree
import de.fraunhofer.aisec.cpg.query.allExtended
import de.fraunhofer.aisec.cpg.query.ge

/**
 * The minimum key length for symmetric encryption algorithms. According to BSI TR-02102-1, this
 * should be at least 256 bits.
 */
const val SYM_KEYLENGTH = 256

/** The list of allowed ciphers for block device encryption. */
val allowedCiphers = listOf("aes-xts-plain64", "aes-cbc-essiv")

/**
 * The block device encryption algorithm must be state of the art, e.g., refer to a TR.
 *
 * This query enforces the following statement: "Given a block device encryption E, if an encryption
 * algorithm A is employed, then A must be a state-of-the-art cryptographic algorithm (e.g., BSI
 * TR-02102-1)"
 *
 * Note that BSI TR-02102-1 only mentions aes-xts as having "relatively good security properties and
 * efficiency"
 */
context(TranslationResult)
fun stateOfTheArtEncryptionIsUsed(): QueryTree<Boolean> {
    val tr = this@TranslationResult

    // We currently allow the two ciphers aes-xts-plain64 and aes-cbc-essiv.
    // This could be extracted to a variable outside this statement.
    val allowedCiphers = listOf("aes-xts-plain64", "aes-cbc-essiv")

    // The predicate must hold for all DiskEncryption concepts.
    return tr.allExtended<DiskEncryption>() {
        // The cipher's name must be in the list of allowed ciphers.
        // We use the Query-API's infix function `IN` for the check.
        // Since this function requires a QueryTree object as input,
        // we use manually create one based on the cipher's name.
        QueryTree(it.cipher?.cipherName) IN allowedCiphers
    }
}

/**
 * The block device encryption algorithm must be state of the art, e.g., refer to a TR.
 *
 * This query enforces the following statement: "Given a block device encryption E, if an encryption
 * algorithm A is employed, A must support a minimum key length L with L >= 256."
 */
context(TranslationResult)
fun minimalKeyLengthIsEnforced(): QueryTree<Boolean> {
    val tr = this@TranslationResult

    // The inner predicate has to hold for each DiskEncryption concept
    val tree =
        tr.allExtended<DiskEncryption> {
            // Get the key of the DiskEncryption concept and its size.
            // If the key is `null`, we do not really know and set the size to 0.
            // Then, compare it with the SYM_KEYLENGTH (which is 256).
            // It has to be greater or equal (infix function `ge` of the Query-API).
            // Since this function requires a QueryTree object as input,
            // we use create with the Query-API's `const` function.
            (it.key?.keySize ?: 0) ge SYM_KEYLENGTH
        }

    return tree
}

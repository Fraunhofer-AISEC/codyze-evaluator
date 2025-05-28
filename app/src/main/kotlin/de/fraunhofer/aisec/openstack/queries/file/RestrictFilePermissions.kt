/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.queries.file

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.Backward
import de.fraunhofer.aisec.cpg.graph.GraphToFollow
import de.fraunhofer.aisec.cpg.graph.Interprocedural
import de.fraunhofer.aisec.cpg.graph.concepts.crypto.encryption.Secret
import de.fraunhofer.aisec.cpg.graph.concepts.file.*
import de.fraunhofer.aisec.cpg.query.*

val permissionsOnWritePredicate = { writeOp: WriteFile ->
    // For each of these `WriteFile` operations, the file mask must
    // be set to 0o600 before the write operation. We check this on
    // each execution path.
    executionPath(
        // We start with the WriteFile operation
        startNode = writeOp,
        // The requirement has to be fulfilled on each path, so we
        // use the `Must` analysis.
        type = Must,
        // We start from the WriteFile op and go backwards in the EOG.
        direction = Backward(GraphToFollow.EOG),
        // We want to explore paths across functions
        scope = Interprocedural(),
        // We check if the file mask is set to 0o600. This is done
        // by the SetFileMask operation.
        predicate = { it is SetFileMask && it.mask == 0x180L /* 0x180 == 0o600 */ },
    )
}

/** This selector can be used to select [WriteFile] operations. */
typealias WriteFileSelector = ((WriteFile) -> Boolean)?

/**
 * This selector can be used to select all [WriteFile] operations.
 *
 * If this selector is used, the query will check all [WriteFile] operations in the translation
 * result.
 */
val AllWritesToFile: WriteFileSelector = null

/**
 * This selector can be used to select only those [WriteFile] operations which are preceded by a
 * `Secret` operation.
 *
 * If this selector is used, the query will check only those [WriteFile] operations which are
 * preceded by a [Secret] operation in the data flow.
 */
val OnlyWritesFromASecret: WriteFileSelector = { writeOp ->
    dataFlow(
            startNode = writeOp,
            type = May,
            direction = Backward(GraphToFollow.DFG),
            scope = Interprocedural(),
            predicate = { it is Secret },
        )
        .value
}

/**
 * Restrictive file permissions should be set when writing files.
 *
 * This query has the following interpretation of this statement: If data is written to a file by a
 * `WriteFile` operation, the file mask must be set to `0o600` before the write-operation.
 *
 * The parameter [select] can be used to restrict the query to only those `WriteFile` operations,
 * e.g. to ones are preceded by a `Secret` operation (see [OnlyWritesFromASecret]).
 */
context(TranslationResult)
fun restrictiveFilePermissionsAreAppliedWhenWriting(
    select: WriteFileSelector = AllWritesToFile
): QueryTree<Boolean> {
    val tr = this@TranslationResult

    // The requirement has to hold for all `WriteFile` operations where the
    // input has an incoming dataflow from a `GetSecret` operation.
    return tr.allExtended<WriteFile>(sel = select, mustSatisfy = permissionsOnWritePredicate)
}

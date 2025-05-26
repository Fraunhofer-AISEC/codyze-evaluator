/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.queries.accesscontrol

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.Backward
import de.fraunhofer.aisec.cpg.graph.GraphToFollow
import de.fraunhofer.aisec.cpg.graph.Interprocedural
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.*
import de.fraunhofer.aisec.cpg.graph.concepts.file.*
import de.fraunhofer.aisec.cpg.query.*

/**
 * Restrictive file permissions should be set.
 *
 * This query has the following interpretation of this statement: If data retrieved from a
 * `GetSecret` operation is written to a file by a `WriteFile` operation, the file mask must be set
 * to `0o600` before the write-operation.
 */
fun restrictFilePermissions(tr: TranslationResult): QueryTree<Boolean> {
    // The requirement has to hold for all `WriteFile` operations where the
    // input has an incoming dataflow from a `GetSecret` operation.
    return tr.allExtended<WriteFile>(
        sel = { writeOp ->
            dataFlow(
                    startNode = writeOp,
                    type = May,
                    direction = Backward(GraphToFollow.DFG),
                    scope = Interprocedural(),
                    predicate = { it is GetSecret },
                )
                .value
        },
        mustSatisfy = { writeOp ->
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
        },
    )
}

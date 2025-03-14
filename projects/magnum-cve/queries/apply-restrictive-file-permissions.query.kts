import de.fraunhofer.aisec.cpg.graph.concepts.file.*
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.*

/*fun statement1(tr: TranslationResult): QueryTree<Boolean> {
    return tr.allExtended<WriteFile>(
        mustSatisfy = { writeOp ->
            executionPath(
                startNode = writeOp,
                type = Must,
                direction = Backward(GraphToFollow.EOG),
                scope = Interprocedural(),
                predicate = {
                    it is SetFileMask && it.mask == 0x180L /* 0x180 == 0o600 */
                },
            )
        }
    )
}*/

fun statement1(tr: TranslationResult): QueryTree<Boolean> {
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
            executionPath(
                startNode = writeOp,
                type = Must,
                direction = Backward(GraphToFollow.EOG),
                scope = Interprocedural(),
                predicate = {
                    it is SetFileMask && it.mask == 0x180L /* 0x180 == 0o600 */
                },
            )
        },
    )
}

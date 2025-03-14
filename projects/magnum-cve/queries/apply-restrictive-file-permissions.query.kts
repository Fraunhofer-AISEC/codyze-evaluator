import de.fraunhofer.aisec.cpg.graph.concepts.file.*

fun statement1(tr: TranslationResult): QueryTree<Boolean> {
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
}

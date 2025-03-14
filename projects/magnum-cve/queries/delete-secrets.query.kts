import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.*
import de.fraunhofer.aisec.cpg.graph.concepts.memory.*

fun statement1(tr: TranslationResult): QueryTree<Boolean> {
    return tr.allExtended<GetSecret>(
        sel = null,
        mustSatisfy = { secret ->
            secret.alwaysFlowsTo(
                scope = Interprocedural(maxSteps = 100),
                sensitivities = FilterUnreachableEOG + FieldSensitive + ContextSensitive,
                predicate = { it is DeAllocate }, // Anforderung: de-allocate the data
            )
        },
    )
}

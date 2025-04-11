import de.fraunhofer.aisec.cpg.*
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.*
import de.fraunhofer.aisec.cpg.graph.concepts.logging.*

fun statement1(tr: TranslationResult): QueryTree<Boolean> {
    return tr.allExtended<Secret> { secret ->
        not(
            dataFlow(
                // The source is any data with the Concept `Secret`.
                startNode = secret,
                // May analysis because a single data flow is enough to violate the requirement
                type = May,
                // Consider all paths across functions.
                scope = Interprocedural(),
                // Use Operation `LogWrite` as a sink.
                predicate = { it is LogWrite },
            ) // If this returns a QueryTree<Boolean> with value `true`, a dataflow may be present.
        ) // We want to negate this result because such a flow must not happen.
    }
}
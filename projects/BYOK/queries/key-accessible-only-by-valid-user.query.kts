import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.GetSecret
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression

fun statement1(tr: TranslationResult): QueryTree<Boolean> {
    fun Node.dataLeavesComponent(): Boolean {
        val whitelist = listOf<HttpEndpoint>()
        // TODO: This should be replaced with the respective operations (writing to a file,
        //  printing, executing commands, logging)
        return ((this is CallExpression) &&
                (this.name.localName == "write" ||
                        this.name.localName == "println" ||
                        this.name.localName == "execute" ||
                        this.name.localName == "log")) || (this is HttpEndpoint && this !in whitelist)
    }

    val noKeyLeakResult =
        tr.allExtended<GetSecret> { secret ->
            not(
                dataFlow(
                    startNode = secret,
                    type = May,
                    scope = Interprocedural(),
                    predicate = { it.dataLeavesComponent() },
                )
            )
       }

    return noKeyLeakResult
}

fun statement2(tr: TranslationResult): QueryTree<Boolean> {
    return QueryTree(true)
}

fun statement3(tr: TranslationResult): QueryTree<Boolean> {
    return QueryTree(true)
}

fun statement4(tr: TranslationResult): QueryTree<Boolean> {
    return QueryTree(true)
}

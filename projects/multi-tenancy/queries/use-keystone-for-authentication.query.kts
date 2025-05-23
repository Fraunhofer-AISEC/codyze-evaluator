import de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationOptionSource


// Todo delete this

fun statement1(tr: TranslationResult): QueryTree<Boolean> {
    return tr.allExtended<ConfigurationOptionSource>(
        sel = { it.name.localName == "auth_strategy" },
        mustSatisfy = {
            QueryTree<Boolean>(
                value = it.evaluate().toString() == "keystone",
                stringRepresentation = "Component config: ${it.location?.artifactLocation}",
            )
        },
    )
}
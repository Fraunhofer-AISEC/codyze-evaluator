import de.fraunhofer.aisec.cpg.graph.concepts.config.Configuration
import de.fraunhofer.aisec.cpg.graph.declarations.FieldDeclaration


fun statement1(tr: TranslationResult): QueryTree<Boolean> {
    return tr.allExtended<ConfigurationOptionSource>(
        sel = { it.name.localName == "auth_strategy" },
        mustSatisfy = {
            val field = it.underlyingNode as? FieldDeclaration
            val result = field?.evaluate().toString() == "keystone"
            QueryTree<Boolean>(
                result,
                stringRepresentation = "Component config: ${it.location?.artifactLocation}",
            )
        },
    )
}
/*
 * This file is part of the OpenStack Checker
 */
import de.fraunhofer.aisec.codyze.AnalysisProject
import de.fraunhofer.aisec.codyze.AnalysisResult
import de.fraunhofer.aisec.codyze.toSarif
import de.fraunhofer.aisec.cpg.TranslationConfiguration
import de.fraunhofer.aisec.cpg.TranslationManager
import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.declarations.TranslationUnitDeclaration
import de.fraunhofer.aisec.cpg.query.QueryTree
import io.github.detekt.sarif4k.MultiformatMessageString
import io.github.detekt.sarif4k.ReportingDescriptor
import io.github.detekt.sarif4k.Run
import io.github.detekt.sarif4k.SarifSchema210
import io.github.detekt.sarif4k.Tool
import io.github.detekt.sarif4k.ToolComponent
import io.github.detekt.sarif4k.Version
import java.io.File
import java.nio.file.Path
import java.util.function.Consumer
import kotlin.Boolean
import kotlin.Exception
import kotlin.Throws

/**
 * Default way of parsing a list of files into a full CPG. All default passes are applied
 *
 * @param topLevel The directory to traverse while looking for files to parse
 * @param usePasses Whether the analysis should run passes after the initial phase
 * @param configModifier An optional modifier for the config
 * @return A list of [TranslationUnitDeclaration] nodes, representing the CPG roots
 * @throws Exception Any exception thrown during the parsing process
 */
@JvmOverloads
@Throws(Exception::class)
fun analyze(
    files: List<File>,
    topLevel: Path,
    usePasses: Boolean,
    configModifier: Consumer<TranslationConfiguration.Builder>? = null,
): TranslationResult {
    val builder =
        TranslationConfiguration.builder()
            .sourceLocations(files)
            .topLevel(topLevel.toFile())
            .loadIncludes(true)
            .disableCleanup()
            .debugParser(true)
            .failOnError(false)
            .useParallelFrontends(false)
    if (usePasses) {
        builder.defaultPasses()
    }
    configModifier?.accept(builder)
    val config = builder.build()
    val analyzer = TranslationManager.builder().config(config).build()
    val result = analyzer.analyze().get()

    return result
}

fun wrapInAnalysisResult(tr: TranslationResult, trees: List<QueryTree<Boolean>>): AnalysisResult {
    val rules =
        trees.mapIndexed { index, tree ->
            ReportingDescriptor(
                id = "rule$index",
                name = "My Rule",
                shortDescription = MultiformatMessageString(text = "My rule"),
            )
        }

    val results = trees.flatMapIndexed { index, tree -> tree.toSarif("rule$index") }

    val run =
        Run(
            tool = Tool(driver = ToolComponent(name = "Codyze", version = "x.x.x", rules = rules)),
            results = results,
        )

    return AnalysisResult(
        translationResult = tr,
        project = AnalysisProject(null, "ad-hoc", projectDir = null, config = tr.config),
        sarif = SarifSchema210(version = Version.The210, runs = listOf(run)),
    )
}

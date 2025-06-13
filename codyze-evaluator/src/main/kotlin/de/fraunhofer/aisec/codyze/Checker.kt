/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze

import de.fraunhofer.aisec.codyze.dsl.requirement
import de.fraunhofer.aisec.cpg.TranslationConfiguration
import de.fraunhofer.aisec.cpg.passes.concepts.TagOverlaysPass
import de.fraunhofer.aisec.cpg.passes.concepts.TaggingContext
import de.fraunhofer.aisec.cpg.passes.concepts.tag
import kotlin.io.path.Path
import kotlin.io.path.absolute

/**
 * Evaluates a script file with Codyze using the provided profile.
 *
 * @param scriptFile The path to the script file to evaluate.
 * @param profile A function that configures the translation configuration for the analysis.
 * @return The analysis result, or null if the project could not be created.
 */
fun evaluateWithCodyze(
    scriptFile: String,
    profile: (TranslationConfiguration.Builder) -> TranslationConfiguration.Builder,
): AnalysisResult? {
    val absoluteFile = Path(scriptFile).absolute()
    val project = AnalysisProject.fromScript(absoluteFile) { profile(it) }
    val result = project?.analyze() ?: return null

    // Print some performance metrics
    result.translationResult.benchmarkResults.print()

    println("# Analysis Results")

    for (categoryEntry in project.requirementCategories) {
        val category = categoryEntry.value
        println("## Category ${category.id}: ${category.name}\n")

        /*for (requirements in category.requirements) {
            println("- Issue: ${issue.name} (${issue.severity})")
            println("  - Description: ${issue.description}")
            println("  - Confidence: ${issue.confidence}")
        }*/
    }

    for (requirement in result.requirementsResults) {
        println(
            "## Requirement ${requirement.key}: ${requirement.value.value} with confidence ${requirement.value.confidence}"
        )
    }

    return result
}

/** Registers the tagging profiles in the [TranslationConfiguration] builder. */
fun TranslationConfiguration.Builder.taggingProfiles(profiles: TaggingContext.() -> Unit) {
    registerPass<TagOverlaysPass>()
    configurePass<TagOverlaysPass>(TagOverlaysPass.Configuration(tag { apply(profiles) }))
}

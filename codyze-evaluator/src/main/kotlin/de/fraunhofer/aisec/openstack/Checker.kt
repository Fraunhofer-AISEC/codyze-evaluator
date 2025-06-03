/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack

import de.fraunhofer.aisec.codyze.AnalysisProject
import de.fraunhofer.aisec.codyze.AnalysisResult
import de.fraunhofer.aisec.cpg.TranslationConfiguration
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
    return project?.analyze()
}

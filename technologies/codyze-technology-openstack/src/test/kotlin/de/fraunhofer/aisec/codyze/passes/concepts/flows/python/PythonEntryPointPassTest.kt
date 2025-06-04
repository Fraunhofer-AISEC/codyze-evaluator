/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.passes.concepts.flows.python

import de.fraunhofer.aisec.cpg.*
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import kotlin.io.path.Path
import kotlin.test.assertEquals
import org.junit.jupiter.api.Test

/**
 * This test suite contains tests for the [PythonEntryPointPass], which identifies entry points in
 * Python projects based on the `setup.cfg` file.
 */
class PythonEntryPointPassTest {

    /** Test case to check if the [PythonEntryPointPass] correctly skips empty components. */
    @Test
    fun testEmpty() {
        val topLevel = Path("src/test/resources/entrypoints")

        val config =
            TranslationConfiguration.builder()
                .sourceLocations(topLevel.toFile())
                .softwareComponents(
                    mutableMapOf("empty" to listOf(topLevel.resolve("empty").toFile()))
                )
                .defaultPasses()
                .registerLanguage<PythonLanguage>()
                .registerPass<PythonEntryPointPass>()
                .useParallelFrontends(true)
                .build()
        config.topLevels.put("empty", topLevel.resolve("empty").toFile())

        val translationManager = TranslationManager.builder().config(config).build()
        val translationResult = translationManager.analyze().get()

        // component not recognized as Python -> should be skipped without errors and no entry
        // points
        val components = translationResult.components.filter { it.name.equals("empty") }
        assertEquals(components.size, 1)
        assert(components.first().incomingInteractions.isEmpty())
    }

    /**
     * Test case to check if the [PythonEntryPointPass] correctly skips components without a
     * `setup.cfg` file.
     */
    @Test
    fun testNoSetupCfg() {
        val topLevel = Path("src/test/resources/entrypoints")

        val config =
            TranslationConfiguration.builder()
                .sourceLocations(topLevel.toFile())
                .softwareComponents(
                    mutableMapOf(
                        "no-setup-cfg" to listOf(topLevel.resolve("no-setup-cfg").toFile())
                    )
                )
                .defaultPasses()
                .registerLanguage<PythonLanguage>()
                .registerPass<PythonEntryPointPass>()
                .useParallelFrontends(true)
                .build()
        config.topLevels.put("no-setup-cfg", topLevel.resolve("no-setup-cfg").toFile())

        val translationManager = TranslationManager.builder().config(config).build()
        val translationResult = translationManager.analyze().get()

        // does not further process component and skips Jep -> no entry points
        val components = translationResult.components.filter { it.name.equals("no-setup-cfg") }
        assertEquals(components.size, 1)
        assert(components.first().incomingInteractions.isEmpty())
    }

    /**
     * Test case to check if the [PythonEntryPointPass] correctly handles components with no entry
     * points but a valid `setup.cfg` file.
     */
    @Test
    fun testNoEntryPoints() {
        val topLevel = Path("src/test/resources/entrypoints")

        val config =
            TranslationConfiguration.builder()
                .sourceLocations(topLevel.toFile())
                .softwareComponents(
                    mutableMapOf(
                        "no-entry-points" to listOf(topLevel.resolve("no-entry-points").toFile())
                    )
                )
                .defaultPasses()
                .registerLanguage<PythonLanguage>()
                .registerPass<PythonEntryPointPass>()
                .useParallelFrontends(true)
                .build()
        config.topLevels.put("no-entry-points", topLevel.resolve("no-entry-points").toFile())

        val translationManager = TranslationManager.builder().config(config).build()
        val translationResult = translationManager.analyze().get()

        // parses `setup.cfg`, gets empty map of entry points and continues -> no entry points
        val components = translationResult.components.filter { it.name.equals("no-entry-points") }
        assertEquals(components.size, 1)
        assert(components.first().incomingInteractions.isEmpty())
    }

    /**
     * Test case to check if the [PythonEntryPointPass] correctly identifies entry points in a
     * Python module based on the `setup.cfg` file.
     */
    @Test
    fun testModule() {
        val topLevel = Path("src/test/resources/entrypoints")

        val config =
            TranslationConfiguration.builder()
                .sourceLocations(topLevel.toFile())
                .softwareComponents(
                    mutableMapOf("module" to listOf(topLevel.resolve("module").toFile()))
                )
                .defaultPasses()
                .registerLanguage<PythonLanguage>()
                .registerPass<PythonEntryPointPass>()
                .useParallelFrontends(true)
                .build()
        config.topLevels.put("module", topLevel.resolve("module").toFile())

        val translationManager = TranslationManager.builder().config(config).build()
        val translationResult = translationManager.analyze().get()

        // parses `setup.cfg` and creates defined entry points
        val components = translationResult.components.filter { it.name.equals("module") }
        assertEquals(components.size, 1)

        val pyComp = components.first()
        assertEquals(pyComp.incomingInteractions.size, 2)

        val pyEntryPoints = translationResult.conceptNodes.filter { it is PythonEntryPoint }
        assertEquals(pyEntryPoints.size, 2)
    }
}

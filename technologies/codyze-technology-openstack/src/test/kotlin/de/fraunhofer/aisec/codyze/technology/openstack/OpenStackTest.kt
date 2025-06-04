/*
 * This file is part of the OpenStack Checker
 */
import de.fraunhofer.aisec.codyze.openstack.passes.*
import de.fraunhofer.aisec.codyze.passes.openstack.http.HttpPecanLibPass
import de.fraunhofer.aisec.cpg.*
import de.fraunhofer.aisec.cpg.frontends.python.*
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.crypto.encryption.*
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.*
import de.fraunhofer.aisec.cpg.graph.concepts.memory.*
import de.fraunhofer.aisec.cpg.graph.edges.*
import de.fraunhofer.aisec.cpg.graph.statements.expressions.*
import de.fraunhofer.aisec.cpg.query.*
import java.io.File
import kotlin.io.path.Path
import kotlin.test.*

class OpenStackTest {

    @Test
    fun testBarbicanConstructor() {
        val topLevel3 = Path("external/barbican")
        val config =
            TranslationConfiguration.builder()
                .sourceLocations(
                    listOf(
                        topLevel3.resolve("barbican/api/controllers/versions.py").toFile(),
                        topLevel3.resolve("barbican/api/controllers/secrets.py").toFile(),
                    )
                )
                .topLevel(topLevel3.toFile())
                .defaultPasses()
                .registerLanguage<PythonLanguage>()
                .exclusionPatterns("test")
                .useParallelFrontends(true)
                .build()

        val translationManager = TranslationManager.builder().config(config).build()
        val result = translationManager.analyze().get()
        val secretsController = result.calls["SecretsController"]
        assertNotNull(secretsController)
        assertIs<ConstructExpression>(secretsController)
    }

    @Test
    fun testDeleteKey() {
        val topLevel = Path("external")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerPass<PythonMemoryPass>()
                it.registerPass<SecretPass>()
                it.registerPass<MakeThingsWorkPrototypicallyPass>()
                it.exclusionPatterns("tests", "drivers")
                it.softwareComponents(
                    mutableMapOf(
                        "cinder" to
                            listOf(
                                topLevel.resolve("cinder/cinder/volume/flows").toFile(),
                                topLevel.resolve("cinder/cinder/utils.py").toFile(),
                            )
                    )
                )
                it.topLevels(mapOf("cinder" to topLevel.resolve("cinder").toFile()))
            }
        assertNotNull(result)
        result.benchmarkResults.print()

        val memory = result.allChildrenWithOverlays<Memory>().singleOrNull()
        assertNotNull(memory)
        assertTrue(memory.ops.isNotEmpty())

        val secrets = result.conceptNodes.filterIsInstance<Secret>()
        assertEquals(2, secrets.size)

        val deleteKey =
            result.allExtended<DiskEncryption> {
                val processInput =
                    (it.underlyingNode as? CallExpression)?.argumentEdges?.get("process_input")?.end
                if (processInput == null) {
                    QueryTree(true)
                } else {
                    executionPath(it) { to ->
                        to is DeAllocate &&
                            (to.what as? Reference)?.refersTo ==
                                (processInput as? Reference)?.refersTo
                    }
                }
            }
        assertNotNull(deleteKey)
        assertEquals(true, deleteKey.value)

        wrapInAnalysisResult(result, listOf(deleteKey))
            .writeSarifJson(File("cinder-volume-flows.sarif"))
    }

    @Test
    fun testCinderApiNoCrash() {
        val topLevel = Path("external")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerPass<PythonMemoryPass>()
                it.registerPass<SecretPass>()
                it.registerPass<HttpPecanLibPass>()
                it.registerPass<MakeThingsWorkPrototypicallyPass>()
                it.exclusionPatterns("tests", "drivers")
                it.softwareComponents(
                    mutableMapOf("cinder" to listOf(topLevel.resolve("cinder/cinder/api").toFile()))
                )
                it.topLevels(mapOf("cinder" to topLevel.resolve("cinder").toFile()))
            }
        assertNotNull(result)
        result.benchmarkResults.print()
    }
}

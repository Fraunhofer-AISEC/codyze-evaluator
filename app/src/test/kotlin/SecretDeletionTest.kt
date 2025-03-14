/*
 * This file is part of the OpenStack Checker
 */
import de.fraunhofer.aisec.codyze.toSarif
import de.fraunhofer.aisec.cpg.frontends.ini.IniFileLanguage
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.ContextSensitive
import de.fraunhofer.aisec.cpg.graph.FieldSensitive
import de.fraunhofer.aisec.cpg.graph.FilterUnreachableEOG
import de.fraunhofer.aisec.cpg.graph.Interprocedural
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.GetSecret
import de.fraunhofer.aisec.cpg.graph.concepts.memory.DeAllocate
import de.fraunhofer.aisec.cpg.query.QueryTree
import de.fraunhofer.aisec.cpg.query.allExtended
import de.fraunhofer.aisec.cpg.query.alwaysFlowsTo
import de.fraunhofer.aisec.openstack.passes.PythonMemoryPass
import de.fraunhofer.aisec.openstack.passes.SecureKeyRetrievalPass
import io.github.detekt.sarif4k.Run
import io.github.detekt.sarif4k.SarifSchema210
import io.github.detekt.sarif4k.SarifSerializer
import io.github.detekt.sarif4k.Tool
import io.github.detekt.sarif4k.ToolComponent
import io.github.detekt.sarif4k.Version
import kotlin.io.path.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class SecretDeletionTest {

    @Test
    fun testEverythingDerivedFromSecretMustBeDeletedOnAllPaths() {
        val topLevel = Path("../projects/BYOK/components")
        val result =
            analyze(files = listOf(), topLevel = topLevel, usePasses = true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<SecureKeyRetrievalPass>()
                it.registerPass<PythonMemoryPass>()
                it.exclusionPatterns("tests", "drivers")
                // it.registerFunctionSummaries(File("src/test/resources/function-summaries.yml"))
                it.softwareComponents(
                    mutableMapOf(
                        "cinder" to
                            listOf(
                                topLevel.resolve("cinder/cinder/volume/flows").toFile(),
                                topLevel.resolve("cinder/cinder/utils.py").toFile(),
                            ),
                        "conf" to listOf(topLevel.resolve("conf").toFile()),
                    )
                )
                it.topLevels(
                    mapOf(
                        "cinder" to topLevel.resolve("cinder").toFile(),
                        "conf" to topLevel.resolve("conf").toFile(),
                    )
                )
            }

        assertNotNull(result)

        // For all data which originate from a GetSecret operation, all execution paths must flow
        // through a DeAllocate operation of the respective value

        val queryTreeResult =
            result.allExtended<GetSecret>(
                sel = null,
                mustSatisfy = { secret ->
                    secret.alwaysFlowsTo(
                        scope = Interprocedural(maxSteps = 100),
                        sensitivities = FilterUnreachableEOG + FieldSensitive + ContextSensitive,
                        predicate = { it is DeAllocate }, // Anforderung: de-allocate the data
                    )
                },
            )

        println(queryTreeResult.printNicely())

        val jsonSarif =
            SarifSerializer.toJson(
                SarifSchema210(
                    version = Version.The210,
                    runs =
                        listOf(
                            Run(
                                tool =
                                    Tool(
                                        driver =
                                            ToolComponent(
                                                name = "Codyze",
                                                version = "x.x.x",
                                                rules = listOf(),
                                            )
                                    ),
                                results =
                                    queryTreeResult.children
                                        .map {
                                            (it as QueryTree<Boolean>).toSarif(
                                                "secret-data-must-be-deleted-statement1"
                                            )
                                        }
                                        .flatten(),
                            )
                        ),
                )
            )
        // println(jsonSarif)

        assertEquals(2, queryTreeResult.children.size)
        val key =
            queryTreeResult.children.singleOrNull { it.node?.location?.region?.startLine == 509 }
        assertNotNull(key)
        assertTrue(key.value == true)
        assertEquals(2, key.children.size, "There should be two EOG paths")
        assertTrue(
            key.children.all {
                (it.children.singleOrNull()?.value as? List<*>)?.isNotEmpty() == true
            },
            "There should be some nodes in the path",
        )

        val new_key =
            queryTreeResult.children.singleOrNull { it.node?.location?.region?.startLine == 515 }
        assertNotNull(new_key)
        assertTrue(new_key.value == false)
        assertTrue(new_key.children.size > 2, "There should be multiple EOG paths")
        assertTrue(
            new_key.children.all {
                (it.children.singleOrNull()?.value as? List<*>)?.isNotEmpty() == true
            },
            "There should be some nodes in the path",
        )

        assertFalse(queryTreeResult.value)
    }
}

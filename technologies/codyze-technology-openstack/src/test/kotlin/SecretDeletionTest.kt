/*
 * This file is part of the OpenStack Checker
 */
import de.fraunhofer.aisec.codyze.queries.keymanagement.secretsAreDeletedAfterUsage
import de.fraunhofer.aisec.cpg.frontends.ini.IniFileLanguage
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.passes.concepts.config.ProvideConfigPass
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.IniFileConfigurationSourcePass
import de.fraunhofer.aisec.cpg.passes.concepts.file.python.PythonFileConceptPass
import de.fraunhofer.aisec.openstack.passes.MakeThingsWorkPrototypicallyPass
import de.fraunhofer.aisec.openstack.passes.OsloConfigPass
import de.fraunhofer.aisec.openstack.passes.PythonMemoryPass
import de.fraunhofer.aisec.openstack.passes.SecureKeyRetrievalPass
import kotlin.io.path.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class SecretDeletionTest {

    @Test
    fun testMagnumKeyDelete() {
        val topLevel = Path("external/magnum")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<OsloConfigPass>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.registerPass<ProvideConfigPass>()
                it.registerPass<PythonFileConceptPass>()
                it.registerPass<MakeThingsWorkPrototypicallyPass>()
                it.registerPass<PythonMemoryPass>()
                it.exclusionPatterns("tests")
                it.softwareComponents(
                    mutableMapOf("magnum" to listOf(topLevel.resolve("magnum").toFile()))
                )
                it.topLevels(mapOf("magnum" to topLevel.resolve("magnum").toFile()))
            }
        assertNotNull(result)

        with(result) {
            // Checks that before each file write operation, there is an operation setting the
            // correct access rights to write only.
            val deleteSecrets = secretsAreDeletedAfterUsage()
            println(deleteSecrets.printNicely())
        }
    }

    @Test
    fun testEverythingDerivedFromSecretMustBeDeletedOnAllPaths() {
        val topLevel = Path("external")
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

        with(result) {
            // For all data which originate from a GetSecret operation, all execution paths must
            // flow through a DeAllocate operation of the respective value

            val allSecretsDeletedOnEOGPaths = secretsAreDeletedAfterUsage()
            println(allSecretsDeletedOnEOGPaths.printNicely())

            assertEquals(2, allSecretsDeletedOnEOGPaths.children.size)
            val key =
                allSecretsDeletedOnEOGPaths.children.singleOrNull {
                    it.node?.location?.region?.startLine == 509
                }
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
                allSecretsDeletedOnEOGPaths.children.singleOrNull {
                    it.node?.location?.region?.startLine == 515
                }
            assertNotNull(new_key)
            assertTrue(new_key.value == false)
            assertTrue(new_key.children.size > 2, "There should be multiple EOG paths")
            assertTrue(
                new_key.children.all {
                    (it.children.singleOrNull()?.value as? List<*>)?.isNotEmpty() == true
                },
                "There should be some nodes in the path",
            )

            assertFalse(allSecretsDeletedOnEOGPaths.value)
        }
    }
}

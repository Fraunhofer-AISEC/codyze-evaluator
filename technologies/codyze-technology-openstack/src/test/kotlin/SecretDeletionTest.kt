/*
 * This file is part of the OpenStack Checker
 */
import de.fraunhofer.aisec.codyze.queries.keymanagement.secretsAreDeletedAfterUsage
import de.fraunhofer.aisec.codyze.technology.openstack.*
import de.fraunhofer.aisec.cpg.graph.concepts.crypto.encryption.*
import kotlin.io.path.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * This test suite contains tests for the deletion of secrets in OpenStack projects, ensuring that
 * secrets are properly deleted after their usage, particularly in the context of [Cinder] and
 * [Magnum].
 */
class SecretDeletionTest {

    /**
     * Test case to see whether the [Secret] used as a key for disk encryption is correctly
     * identified and deleted in [Cinder].
     */
    @Test
    fun testSecretsAreDeletedAfterUsageMagnum() {
        val topLevel = Path("external/magnum")
        val result =
            analyze(listOf(), topLevel, true) {
                OpenStackProfile(it)
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

    /**
     * Test case to see whether all secrets derived from a [Secret] are deleted on all execution
     * paths in [Cinder].
     */
    @Test
    fun testSecretsAreDeletedAfterUsageCinder() {
        val topLevel = Path("external")
        val result =
            analyze(files = listOf(), topLevel = topLevel, usePasses = true) {
                OpenStackProfile(it)
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

            val newKey =
                allSecretsDeletedOnEOGPaths.children.singleOrNull {
                    it.node?.location?.region?.startLine == 515
                }
            assertNotNull(newKey)
            assertTrue(newKey.value == false)
            assertTrue(newKey.children.size > 2, "There should be multiple EOG paths")
            assertTrue(
                newKey.children.all {
                    (it.children.singleOrNull()?.value as? List<*>)?.isNotEmpty() == true
                },
                "There should be some nodes in the path",
            )

            assertFalse(allSecretsDeletedOnEOGPaths.value)
        }
    }
}

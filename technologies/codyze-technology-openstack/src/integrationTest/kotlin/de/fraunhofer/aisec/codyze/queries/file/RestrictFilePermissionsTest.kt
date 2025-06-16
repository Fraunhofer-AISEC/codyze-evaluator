/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.queries.file

import de.fraunhofer.aisec.codyze.analyze
import de.fraunhofer.aisec.codyze.passes.concepts.config.openstack.OsloConfigPass
import de.fraunhofer.aisec.codyze.profiles.openstack.*
import de.fraunhofer.aisec.cpg.frontends.ini.IniFileLanguage
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.passes.concepts.TagOverlaysPass
import de.fraunhofer.aisec.cpg.passes.concepts.config.ProvideConfigPass
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.IniFileConfigurationSourcePass
import de.fraunhofer.aisec.cpg.passes.concepts.file.python.PythonFileConceptPass
import de.fraunhofer.aisec.cpg.passes.concepts.tag
import kotlin.io.path.Path
import kotlin.test.*

/** This test suite contains tests for file-based queries using the [OpenStackProfile]. */
class RestrictFilePermissionsTest {

    /**
     * Test case for [restrictiveFilePermissionsAreAppliedWhenWriting] using [OpenStackProfile]. The
     * analyzed component is [Magnum].
     */
    @Test
    fun testRestrictiveFilePermissionsAreAppliedWhenWritingAll() {
        val topLevel = Path("external/magnum")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<OsloConfigPass>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.registerPass<ProvideConfigPass>()
                it.registerPass<PythonFileConceptPass>()
                it.registerPass<TagOverlaysPass>()
                it.configurePass<TagOverlaysPass>(
                    TagOverlaysPass.Configuration(
                        tag {
                            // Use a predefined tagging profile for secret definitions in OpenStack.
                            decryptedCertToSecret()
                            getSecretPluginCall()
                        }
                    )
                )
                it.exclusionPatterns("tests")
                it.softwareComponents(
                    mutableMapOf("magnum" to listOf(topLevel.resolve("magnum").toFile()))
                )
                it.topLevels(mapOf("magnum" to topLevel.resolve("magnum").toFile()))
            }
        assertNotNull(result)

        // Checks that before each file write operation, there is an operation setting the correct
        // access rights to write only.
        with(result) {
            val setMaskBeforeWrite =
                restrictiveFilePermissionsAreAppliedWhenWriting(select = AllWritesToFile)
            assertFalse(setMaskBeforeWrite.value)
        }
    }

    /**
     * Test case for [restrictiveFilePermissionsAreAppliedWhenWriting] using [OpenStackProfile]. The
     * analyzed component is [Magnum], but only the secret data is considered.
     */
    @Test
    fun testFileChmodForSecretData() {
        val topLevel = Path("external/magnum")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<OsloConfigPass>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.registerPass<ProvideConfigPass>()
                it.registerPass<PythonFileConceptPass>()
                it.registerPass<TagOverlaysPass>()
                it.configurePass<TagOverlaysPass>(
                    TagOverlaysPass.Configuration(
                        tag {
                            // Use a predefined tagging profile for secret definitions in OpenStack.
                            decryptedCertToSecret()
                            getSecretPluginCall()
                        }
                    )
                )
                it.exclusionPatterns("tests")
                it.softwareComponents(
                    mutableMapOf("magnum" to listOf(topLevel.resolve("magnum").toFile()))
                )
                it.topLevels(mapOf("magnum" to topLevel.resolve("magnum").toFile()))
            }
        assertNotNull(result)

        // Checks that before each file write operation, there is an operation setting the correct
        // access rights to write only.
        val setMaskBeforeWrite =
            with(result) {
                restrictiveFilePermissionsAreAppliedWhenWriting(select = OnlyWritesFromASecret)
            }

        assertTrue(setMaskBeforeWrite.value)
    }
}

/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.passes.concepts.file.python

import de.fraunhofer.aisec.codyze.analyze
import de.fraunhofer.aisec.codyze.passes.concepts.config.openstack.OsloConfigPass
import de.fraunhofer.aisec.codyze.profiles.openstack.Magnum
import de.fraunhofer.aisec.codyze.profiles.openstack.decryptedCertToSecret
import de.fraunhofer.aisec.codyze.profiles.openstack.getSecretPluginCall
import de.fraunhofer.aisec.cpg.frontends.ini.IniFileLanguage
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.concepts.Operation
import de.fraunhofer.aisec.cpg.graph.concepts.file.File
import de.fraunhofer.aisec.cpg.graph.operationNodes
import de.fraunhofer.aisec.cpg.passes.concepts.TagOverlaysPass
import de.fraunhofer.aisec.cpg.passes.concepts.config.ProvideConfigPass
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.IniFileConfigurationSourcePass
import de.fraunhofer.aisec.cpg.passes.concepts.file.python.PythonFileConceptPass
import de.fraunhofer.aisec.cpg.passes.concepts.tag
import kotlin.io.path.Path
import kotlin.test.*

/**
 * This test suite contains tests to check if file concepts (such as [File]) are correctly applied
 * to OpenStack components using [PythonFileConceptPass].
 */
class FileTest {

    /**
     * Test case to check if duplicate [Operation] nodes are not created during the analysis of
     * OpenStack [Magnum]
     */
    @Test
    fun testDuplicateOperationNodes() {
        val topLevel = Path("external/magnum")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<OsloConfigPass>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.registerPass<ProvideConfigPass>()
                it.registerPass<PythonFileConceptPass>()
                it.exclusionPatterns("tests")
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
                it.softwareComponents(
                    mutableMapOf("magnum" to listOf(topLevel.resolve("magnum").toFile()))
                )
                it.topLevels(mapOf("magnum" to topLevel.resolve("magnum").toFile()))
            }
        assertNotNull(result)

        val operationNode = result.operationNodes
        assertTrue(operationNode.isNotEmpty(), "Expected to find some `Operation` nodes.")
        assertTrue(
            operationNode.groupBy { it }.filter { it.value.size > 1 }.isEmpty(),
            "Found at least two equal `Operation` nodes. Expected to not find any duplicates.",
        )
    }
}

/*
 * This file is part of the OpenStack Checker
 */
import de.fraunhofer.aisec.cpg.frontends.ini.IniFileLanguage
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.operationNodes
import de.fraunhofer.aisec.cpg.passes.concepts.config.ProvideConfigPass
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.IniFileConfigurationSourcePass
import de.fraunhofer.aisec.cpg.passes.concepts.file.python.PythonFileConceptPass
import de.fraunhofer.aisec.openstack.passes.MakeThingsWorkPrototypicallyPass
import de.fraunhofer.aisec.openstack.passes.OsloConfigPass
import de.fraunhofer.aisec.openstack.queries.accesscontrol.restrictPermissionsForAllWrites
import de.fraunhofer.aisec.openstack.queries.accesscontrol.restrictPermissionsOfSecretWriting
import kotlin.io.path.Path
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class FileTest {
    @Test
    fun testDuplicateOperationNodes() {
        val topLevel = Path("../external/magnum")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<OsloConfigPass>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.registerPass<ProvideConfigPass>()
                it.registerPass<PythonFileConceptPass>()
                it.registerPass<MakeThingsWorkPrototypicallyPass>()
                it.exclusionPatterns("tests")
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

    @Test
    fun testFileChmod() {
        val topLevel = Path("../external/magnum")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<OsloConfigPass>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.registerPass<ProvideConfigPass>()
                it.registerPass<PythonFileConceptPass>()
                it.registerPass<MakeThingsWorkPrototypicallyPass>()
                it.exclusionPatterns("tests")
                it.softwareComponents(
                    mutableMapOf("magnum" to listOf(topLevel.resolve("magnum").toFile()))
                )
                it.topLevels(mapOf("magnum" to topLevel.resolve("magnum").toFile()))
            }
        assertNotNull(result)

        // Checks that before each file write operation, there is an operation setting the correct
        // access rights to write only.
        val setMaskBeforeWrite = restrictPermissionsForAllWrites(result)
        println(setMaskBeforeWrite.printNicely())
    }

    @Test
    fun testFileChmodForSecretData() {
        val topLevel = Path("../external/magnum")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<OsloConfigPass>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.registerPass<ProvideConfigPass>()
                it.registerPass<PythonFileConceptPass>()
                it.registerPass<MakeThingsWorkPrototypicallyPass>()
                it.exclusionPatterns("tests")
                it.softwareComponents(
                    mutableMapOf("magnum" to listOf(topLevel.resolve("magnum").toFile()))
                )
                it.topLevels(mapOf("magnum" to topLevel.resolve("magnum").toFile()))
            }
        assertNotNull(result)

        // Checks that before each file write operation, there is an operation setting the correct
        // access rights to write only.
        val setMaskBeforeWrite = restrictPermissionsOfSecretWriting(result)
        println(setMaskBeforeWrite.printNicely())
    }
}

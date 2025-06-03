/*
 * This file is part of the OpenStack Checker
 */
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.DiskEncryption
import de.fraunhofer.aisec.cpg.graph.invoke
import de.fraunhofer.aisec.openstack.passes.DiskEncryptionPass
import de.fraunhofer.aisec.openstack.passes.SecretPass
import kotlin.io.path.Path
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DiskEncryptionTest {
    @Test
    fun testDiskEncryption() {
        val topLevel = Path("external/cinder")
        val result =
            analyze(
                files =
                    listOf(
                        topLevel.resolve("cinder/volume/flows/manager/create_volume.py").toFile(),
                        topLevel.resolve("cinder/utils.py").toFile(),
                    ),
                topLevel = topLevel,
                usePasses = true,
                persistNeo4j = false,
            ) {
                it.registerLanguage<PythonLanguage>()
                it.registerPass<DiskEncryptionPass>()
                it.registerPass<SecretPass>()
            }

        assertNotNull(result)

        val diskEnc = result.conceptNodes.filterIsInstance<DiskEncryption>()
        assertTrue(diskEnc.isNotEmpty())
    }
}

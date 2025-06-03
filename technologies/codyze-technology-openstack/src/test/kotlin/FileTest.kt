/*
 * This file is part of the OpenStack Checker
 */
import de.fraunhofer.aisec.codyze.queries.file.AllWritesToFile
import de.fraunhofer.aisec.codyze.queries.file.OnlyWritesFromASecret
import de.fraunhofer.aisec.codyze.queries.file.restrictiveFilePermissionsAreAppliedWhenWriting
import de.fraunhofer.aisec.cpg.graph.operationNodes
import kotlin.io.path.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class FileTest {
    @Test
    fun testDuplicateOperationNodes() {
        val topLevel = Path("external/magnum")
        val result = analyze(listOf(), topLevel, true)
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
        val topLevel = Path("external/magnum")
        val result = analyze(listOf(), topLevel, true)
        assertNotNull(result)

        // Checks that before each file write operation, there is an operation setting the correct
        // access rights to write only.
        with(result) {
            val setMaskBeforeWrite =
                restrictiveFilePermissionsAreAppliedWhenWriting(select = AllWritesToFile)
            assertFalse(setMaskBeforeWrite.value)
        }
    }

    @Test
    fun testFileChmodForSecretData() {
        val topLevel = Path("external/magnum")
        val result = analyze(listOf(), topLevel, true)
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

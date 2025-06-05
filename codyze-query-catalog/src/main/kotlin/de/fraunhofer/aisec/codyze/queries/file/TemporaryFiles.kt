/*
 * This file is part of the OpenStack Checker
 */
import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.Forward
import de.fraunhofer.aisec.cpg.graph.GraphToFollow
import de.fraunhofer.aisec.cpg.graph.Interprocedural
import de.fraunhofer.aisec.cpg.graph.concepts.file.DeleteFile
import de.fraunhofer.aisec.cpg.graph.concepts.file.FileTempFileStatus
import de.fraunhofer.aisec.cpg.graph.concepts.file.OpenFile
import de.fraunhofer.aisec.cpg.query.Must
import de.fraunhofer.aisec.cpg.query.QueryTree
import de.fraunhofer.aisec.cpg.query.allExtended
import de.fraunhofer.aisec.cpg.query.executionPath

/** for every temporary file, there is an execution flow to a delete file */
context(TranslationResult)
fun temporaryFilesAreAlwaysDeleted(): QueryTree<Boolean> {
    val tr = this@TranslationResult
    return tr.allExtended<OpenFile>(sel = { it.file.isTempFile == FileTempFileStatus.TEMP_FILE }) {
        openFile ->
        executionPath(
            startNode = openFile,
            direction = Forward(GraphToFollow.EOG),
            type = Must,
            scope = Interprocedural(),
        ) {
            it is DeleteFile && openFile.file == it.file
        }
    }
}

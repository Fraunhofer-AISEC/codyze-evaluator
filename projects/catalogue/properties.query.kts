import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Secret
import de.fraunhofer.aisec.cpg.graph.concepts.file.ReadFile
import de.fraunhofer.aisec.cpg.graph.concepts.file.WriteFile
import de.fraunhofer.aisec.cpg.graph.concepts.logging.LogWrite
import de.bund.bsi.catalgoue.*
import de.bund.bsi.catalgoue.architecture.PlaintextBackupEndpoint
import de.bund.bsi.catalgoue.cryptography.Blockcipherkey
import de.bund.bsi.catalgoue.cryptography.SymmetricEncrypt
import de.bund.bsi.catalgoue.network.HttpResponse
import de.bund.bsi.catalgoue.properties.Asset_Confidentiality
import de.bund.bsi.catalgoue.properties.InformationAnnihilator
import de.bund.bsi.catalgoue.properties.nonConfidentialVariable
import de.bund.bsi.catalgoue.utils.goesIntoInformationAnnihilator
import de.bund.bsi.catalgoue.utils.nodeHasConcept
import de.fraunhofer.aisec.cpg.graph.concepts.Concept
import de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration
import de.fraunhofer.aisec.cpg.passes.concepts.each
import de.fraunhofer.aisec.cpg.passes.concepts.tag
import de.fraunhofer.aisec.cpg.passes.concepts.with
import javax.management.Query


fun checkInformationAnnihilatorsAreCorrectlyUsed(tr: TranslationResult) : QueryTree<Boolean> {

    TODO()
}


fun objectsAreImmutableExceptByListOfFunctions(tr: TranslationResult, listAllowed : List<FunctionDeclaration>) : QueryTree<Boolean> {

    TODO()

}

tag {

    /** Tags each node with Asset_Confidential if there exists a node whose information flows into the node and whose overlay nodes (i.e. its assigned concepts) contains a secret,
     * or more naturally: Tag something as confidential, if it depends on a confidential node. Since errors might happen, one can tag a node explicitly as "nonConfidentialVariable"
     * so all queries respect this.
     */
    each<Node>(predicate =
        { node ->

            dataFlow(node, direction = Backward(GraphToFollow.DFG), type = May, sensitivities = FieldSensitive + ContextSensitive, scope = Interprocedural(),
                earlyTermination = {searchNode ->  goesIntoInformationAnnihilator(searchNode)}, predicate = { nodeHasConcept<Asset_Confidentiality>(it) })

                .and(not( nodeHasConcept<nonConfidentialVariable>(node)) ).value

        }).with{ Asset_Confidentiality(node) }

}





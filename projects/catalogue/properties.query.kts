import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Secret
import de.fraunhofer.aisec.cpg.graph.concepts.file.ReadFile
import de.fraunhofer.aisec.cpg.graph.concepts.file.WriteFile
import de.fraunhofer.aisec.cpg.graph.concepts.logging.LogWrite
import de.bund.bsi.catalgoue.*
import de.bund.bsi.catalgoue.cryptography.Blockcipherkey
import de.bund.bsi.catalgoue.cryptography.SymmetricEncrypt
import de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration
import de.fraunhofer.aisec.cpg.passes.concepts.each
import de.fraunhofer.aisec.cpg.passes.concepts.tag
import de.fraunhofer.aisec.cpg.passes.concepts.with



tag {

    //Tags each node with Secret if there exists a node whose information flows into the node and whose overlay nodes (i.e. its assigned concepts) contains a secret,
    //or more naturally: Tag something as secret, if it depends on a secret
    // add informationAnnihilator
    each<Node>( predicate = {it.prevDFG.any({prevDFGNode -> prevDFGNode.overlays.any({overlayNodes -> overlayNodes is Secret})} )})
        .with { Secret() }

}
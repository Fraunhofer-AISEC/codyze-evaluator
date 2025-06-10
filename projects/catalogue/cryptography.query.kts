import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Secret
import de.fraunhofer.aisec.cpg.graph.concepts.file.ReadFile
import de.fraunhofer.aisec.cpg.graph.concepts.file.WriteFile
import de.fraunhofer.aisec.cpg.graph.concepts.logging.LogWrite
import de.bund.bsi.catalgoue.*
import de.bund.bsi.catalgoue.architecture.PlaintextBackupEndpoint
import de.bund.bsi.catalgoue.cryptography.Blockcipherkey
import de.bund.bsi.catalgoue.cryptography.EntropyPreservingFunction
import de.bund.bsi.catalgoue.cryptography.HMAC
import de.bund.bsi.catalgoue.cryptography.KeyGenerator
import de.bund.bsi.catalgoue.cryptography.MessageAuthenticationCode
import de.bund.bsi.catalgoue.cryptography.SymmetricEncrypt
import de.bund.bsi.catalgoue.network.HttpResponse
import de.bund.bsi.catalgoue.properties.Asset_Confidentiality
import de.bund.bsi.catalgoue.utils.nodeHasConcept
import de.bund.bsi.catalogue.cryptography.Blockcipherkey
import de.bund.bsi.catalogue.cryptography.EntropyPreservingFunction
import de.bund.bsi.catalogue.cryptography.SymmetricEncrypt
import de.bund.bsi.catalogue.utils.nodeHasConcept
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration
import de.fraunhofer.aisec.cpg.passes.concepts.each
import de.fraunhofer.aisec.cpg.passes.concepts.tag
import de.fraunhofer.aisec.cpg.passes.concepts.with
import kotlin.reflect.typeOf




// A blockcipherkey must be the result of a KeyGenerator, and may only be written over by an entropy preserving function
fun blockcipherkeysAreGeneratedByAKeyGeneratorAndPreserveEntropy(tr: TranslationResult) : QueryTree<Boolean>{

    return tr.allExtended<Blockcipherkey>(
        sel = {true},
        mustSatisfy = {bck ->
            dataFlow(
                startNode = bck,
                type = May,
                direction = Backward(GraphToFollow.DFG),
                scope = Interprocedural(),
                earlyTermination = {bck -> !nodeHasConcept<EntropyPreservingFunction>(bck)},
                predicate = {bck -> nodeHasConcept<KeyGenerator>(bck) })
                    }
            )
}


tag {

    // All Blockcipherkeys are confidential
    each<Node>( predicate = { nodeHasConcept<Blockcipherkey>(it) })
        .with { Asset_Confidentiality(null) }

    // HMAC is also a MAC.
    each<Node>( predicate = {nodeHasConcept<HMAC>(it)})
        .with { MessageAuthenticationCode(null) }
}
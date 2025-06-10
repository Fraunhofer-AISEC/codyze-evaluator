#!/usr/bin/env kotlin

import de.bund.bsi.catalogue.architecture.PlaintextBackupEndpoint
import de.bund.bsi.catalogue.cryptography.SymmetricEncrypt
import de.bund.bsi.catalogue.properties.UserInputDependentControlflow
import de.bund.bsi.catalogue.traversal.DomainSeparationMechanism
import de.bund.bsi.catalogue.traversal.DomainSeparationMechanismPart
import de.bund.bsi.catalogue.utils.nodeHasConcept
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Secret
import de.fraunhofer.aisec.cpg.graph.concepts.file.WriteFile
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.concepts.logging.LogWrite
import de.fraunhofer.aisec.cpg.graph.edges.flows.ControlDependence
import de.fraunhofer.aisec.cpg.passes.concepts.tag
import kotlin.test.todo

//Queries to avoid injection attacks

//- Wenn es eine Änderung des Kontrollflusses basierend auf Nutzereingaben gibt, dann kann dies kein Datenfluss zwischen Domänen verursachen. Wenn dieser doch stattfindet, dann
//- in einer DomainSeparationComponent.
//- Beispiel: Die Verify(uname, pw) greift auf eine Tabelle zu, in der Daten aus verschiedenen Domänen gespeichert sind. Verify braucht manuelle überprüfung, dass keine Infos
//- (über Gebühr, wie #Nutzer) geleakt werden. Eine Suche darf die Liste aller VMs anzeigen, die einem Nutzer gehören (änderung Kontrollfluss), aber nicht auf Daten zugreifen,
//- die ihm nicht gehören.

/**
 * Every TOE has at least 3 domains: The outside, the data to be protected from the outside and at least one TOE internal domain in which data can be processed that comes from
 * various different domains an is to be verified (user authentication data), sanitized (error messages), transformed (writing layer 2 network packets into layer 3 packets)
 * and rerouted (mapping the public IP of a VPN-client to its internal-network address).
 * Most likely in a cloud system, there are much more domains, and some domains might even overlap or depend on who's asking and what are his permissions.
 *
 * We have to make sure, that the TOEs behaviour does not depend in a way on user input that allows the user to bypass separation mechanisms.
 * Therefore, we forbid dependency of the control flow on user input if the subprogram executed has access to a resource container that contains resources of different domains,
 * and there are some inputs that make the subprogram access resources of a different domain than 
 */
fun controlDependencyOnUserData_cannotCauseInterDomainDataFlow(tr: TranslationResult) : QueryTree<Boolean>{

    return tr.allExtended<Node>(
        sel = { cntrlBlk -> nodeHasConcept<UserInputDependentControlflow>(cntrlBlk) },
        mustSatisfy = {cntrlBlk -> QueryTree(nodeHasConcept<DomainSeparationMechanismPart>(cntrlBlk))}
    )
}

//If a subroutine is working on a (set of) domainSpecificDataStore, all data read and written must be from this domain.
/**
 * For this, make sure that
 * a) every DataStore is returned by a DomainSeparationMechanism based on a PartitionFunction's output on userInput
 * b) the function cannot access any other resources
 */








/** Secrets used as keys and all things derived from it must not be persisted (except from ciphertexts). */
fun secretKeysDoNotLeaveTheSystem (tr: TranslationResult): QueryTree<Boolean> {
    return tr.allExtended<Secret>(
        sel = { secret -> true},
        mustSatisfy = { secret ->
            // The secret-dependent value must not leave the system except if it is the ciphertext where the secret was used as key.
            not(
                dataFlow(
                    startNode = secret,
                    type = May,
                    direction = Bidirectional(GraphToFollow.DFG),
                    scope = Interprocedural(),
                    // Check if node is valid ciphertext. We do no longer follow such a path.
                    earlyTermination = { node -> onlyUsedAsKey(tr, node, secret) },
                    // HttpEndpoint is probably not the best match -> introduce Http Response as concept.
                    predicate = { it is WriteFile || it is LogWrite || (it is HttpEndpoint && it !is PlaintextBackupEndpoint)  }
                )
            )
        }
    )
}

/**
 * Returns `true` if the parameter `secret` is only used as a key in the encryption function.
 */
fun onlyUsedAsKey(tr: TranslationResult, node: Node, secret: Secret): Boolean {
    TODO()
}


tag {

    //assume that a DomainSeparationMechanism is respecting the different domains, has to be checked by hand?

    //every controlBlock that is part of a DomainSeparationMechanism is a DomainSeparationMechanismPart

    //every controlBlock that is based on a userInput is a UserInputDependentControlFlow
}
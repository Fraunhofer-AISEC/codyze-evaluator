/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.concepts.auth

import de.fraunhofer.aisec.cpg.graph.MetadataProvider
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.newConcept

fun MetadataProvider.newPolicy(underlyingNode: Node, connect: Boolean) =
    newConcept(::Policy, underlyingNode = underlyingNode, connect = connect)

fun MetadataProvider.newPolicyRule(
    underlyingNode: Node,
    concept: Policy,
    roles: Set<Role>,
    connect: Boolean,
) =
    newConcept({ PolicyRule(roles = roles) }, underlyingNode = underlyingNode, connect = connect)
        .apply { concept.rule = this }

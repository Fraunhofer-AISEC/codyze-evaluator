/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.queries.isolation

import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberCallExpression

/** A set of domain identifiers. */
val domainIdentifiers = setOf("project_id", "domain_id")

/**
 * Checks if the [Node] is a [MemberCallExpression] with any argument name matching a value in
 * [domainIdentifiers].
 */
fun Node.hasCheckForDomain(): Boolean {
    return when (this) {
        is MemberCallExpression -> this.argumentEdges.any { arg -> arg.name in domainIdentifiers }

        else -> false
    }
}

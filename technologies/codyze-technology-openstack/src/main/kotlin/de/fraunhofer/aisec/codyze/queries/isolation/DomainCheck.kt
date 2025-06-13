/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.queries.isolation

import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberCallExpression

/** A set of domain identifiers. */
val domainIdentifiers = setOf("project_id", "domain_id")

/**
 * Determines if the [Node] has a check for domain-related identifiers. Returns true if the parent
 * node is a [MemberCallExpression] with any keyword argument matching its name, and when the
 * [Node]`s name is in [domainIdentifiers].
 */
fun Node.hasCheckForDomain(): Boolean {
    return (this.astParent as? MemberCallExpression)?.argumentEdges?.any { arg ->
        arg.name == arg.end.name.localName
    } == true && this.name.localName in domainIdentifiers
}

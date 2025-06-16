/*
 * This file is part of the OpenStack Checker
 */
package example

import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpRequest
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberCallExpression

project {
    suppressions {
        /**
         * This is a suppression for a query that checks for the deletion of secrets. It is known to
         * find a violation if the secret is returned by two known endpoints in the file "secret.py"
         * at lines 129 and 212.
         */
        queryTree(
            { qt: QueryTree<Boolean> ->
                val returnStmtLocation =
                    ((qt.children.singleOrNull()?.value as? List<*>)?.lastOrNull()
                            as? de.fraunhofer.aisec.cpg.graph.statements.ReturnStatement)
                        ?.location
                returnStmtLocation
                    ?.artifactLocation
                    ?.uri
                    ?.path
                    ?.endsWith(
                        "/examples/evaluate-hardened-openstack/toe/modules/barbican/barbican/api/controllers/secrets.py"
                    ) == true &&
                    (returnStmtLocation.region.startLine == 129 ||
                        returnStmtLocation.region.startLine == 212)
            } to true
        )

        queryTree(
            { qt: QueryTree<Boolean> ->
                val lastNode = (qt.children.singleOrNull()?.value as? List<*>)?.lastOrNull()
                lastNode is MemberCallExpression &&
                    lastNode.name.localName == "execute" &&
                    ((lastNode.location
                        ?.artifactLocation
                        ?.uri
                        ?.toString()
                        ?.endsWith("cinder/volume/flows/manager/create_volume.py") == true &&
                        (lastNode.location?.region?.startLine == 605 ||
                            lastNode.location?.region?.startLine == 585)) ||
                        (lastNode.location
                            ?.artifactLocation
                            ?.uri
                            ?.toString()
                            ?.endsWith("cinder/utils.py") == true &&
                            lastNode.location?.region?.startLine == 172) ||
                        (lastNode.location
                            ?.artifactLocation
                            ?.uri
                            ?.toString()
                            ?.endsWith("magnum/conductor/handlers/common/cert_manager.py") ==
                            true &&
                            (lastNode.location?.region?.startLine == 197 ||
                                lastNode.location?.region?.startLine == 169)))
            } to false
        )

        /**
         * This access to the DB explicitly allows to read the default volume type of all projects.
         */
        queryTreeById("00000000-297e-6d16-0000-0000000004f4" to true)

        /**
         * These query trees flow through the line 515 of the file
         * "/examples/evaluate-hardened-openstack/toe/modules/cinder/cinder/volume/flows/manager/create_volume.py".
         * This line contains the following assignment `new_key = keymgr.get(context, new_key_id)`.
         * The `CallExpression` is tagged with a `GetSecret` and a `HttpRequest`. With this, we have
         * several DFG paths reaching new_key, including the `MemberCallExpression`, its base
         * (`keymgr`), the reference `context? and the reference `new_key_id`, too. However, we're
         * only interested in the path across the `HttpRequest` which should supersede the other
         * data flows. As the pass does not replace existing DFG edges but only adds new ones, this
         * is not accurately modeled (to not lose the connections of the "real code").
         *
         * We suppress every dataflow path containing a node which is not the `HttpRequest` since
         * this one invalidates all the rest. The CPG models the rest as alternative paths, which is
         * not what we want here as it is not correct.
         */
        queryTree(
            { qt: QueryTree<Boolean> ->
                (qt.children.singleOrNull()?.value as? List<*>)?.any {
                    it is Node &&
                        it !is HttpRequest &&
                        it.location
                            ?.artifactLocation
                            ?.uri
                            ?.path
                            ?.endsWith(
                                "/examples/evaluate-hardened-openstack/toe/modules/cinder/cinder/volume/flows/manager/create_volume.py"
                            ) == true &&
                        (it.location?.region?.startLine == 515) &&
                        "encryptionKeyOriginatesFromSecureKeyProvider" in qt.callerInfo?.methodName
                } == true
            } to true
        )
    }
}

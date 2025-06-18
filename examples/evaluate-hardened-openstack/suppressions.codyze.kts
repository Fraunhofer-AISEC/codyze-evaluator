/*
 * This file is part of the OpenStack Checker
 */
package example

import de.fraunhofer.aisec.cpg.graph.concepts.file.OpenFile
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpRequest
import de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration
import de.fraunhofer.aisec.cpg.graph.statements.ReturnStatement
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
                            as? ReturnStatement)
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

        /**
         * Keys, which are also secret data, flow into data-leaking functions.
         *
         * This affects three cases which are expected behavior and not malicious:
         * - The `execute` method used for the disk encryption (create_volume.py line 605 and 585).
         *   This also affects (util.py line 172).
         * - The keys are written to temporary cache-files in cert_manager.py lines 169 and 197.
         *   This seems to be used to share the keys with Kubernetes.
         *
         *   These cases are suppressed as they seem to be expected behavior and not malicious.
         */
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
                        it.hasLocation(
                            "/examples/evaluate-hardened-openstack/toe/modules/cinder/cinder/volume/flows/manager/create_volume.py",
                            startLine = 515,
                            endLine = null,
                        ) &&
                        "encryptionKeyOriginatesFromSecureKeyProvider" in
                            (qt.callerInfo?.methodName ?: "")
                } == true
            } to true
        )

        /**
         * There are several paths which return temporary file in the method `create_client_files`.
         * This method is called only by the constructor of the class `KubernetesAPI`
         * (`magnum/conductor/k8s_api.py`). This class has a destructor method (`__del__`) which
         * closes the files and thus deletes the temporary files. This method is called by the VM
         * whenever the object is no longer reachable. This guarantees that the temporary files are
         * always deleted.
         *
         * The suppression accounts for these false positives and suppresses them.
         */
        queryTree(
            { qt: QueryTree<Boolean> ->
                val path = (qt.children.singleOrNull()?.value as? List<*>)
                // The files are returned by this function and deleted on all paths outside.
                val functionDeclaration =
                    (path?.firstOrNull() as? OpenFile)?.underlyingNode?.firstParentOrNull<
                        FunctionDeclaration
                    > {
                        it.name.localName == "create_client_files" &&
                            it.hasLocation(
                                "magnum/conductor/handlers/common/cert_manager.py",
                                startLine = 157,
                                endLine = null,
                            )
                    }

                functionDeclaration != null &&
                    path.any {
                        it is ReturnStatement &&
                            it.hasLocation(
                                "magnum/conductor/handlers/common/cert_manager.py",
                                startLine = 212,
                                endLine = 212,
                            )
                    } &&
                    "temporaryFilesAreAlwaysDeleted" in (qt.callerInfo?.methodName ?: "")
            } to true
        )
    }
}

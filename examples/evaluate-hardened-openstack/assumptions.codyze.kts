/*
 * This file is part of the OpenStack Checker
 */
package example

project {
    assumptions {
        decisions {
            /**
             * We do not have access to the information of the disk encryption algorithm as it is
             * specified in a database. Changes of the database entries may possible through various
             * means. We also cannot compute the values
             */
            reject("00000000-0000-0000-ffff-ffff88d01ccd")
            reject("00000000-0000-0000-0000-0000126c56a4")

            /** We ignore that the inference starts in a record, namespace or translation unit. */
            ignore("00000000-0000-0000-ffff-ffffa1fa084e")
            ignore("00000000-0000-0000-ffff-ffffa1fa084e")
            ignore("00000000-0000-0000-0000-00005bae5c76")
            ignore("00000000-0000-0000-0000-00003c6caf0e")
            ignore("00000000-0000-0000-0000-000077a7e176")
            ignore("00000000-0000-0000-ffff-ffffd1ea8851")
            ignore("00000000-0000-0000-ffff-ffffd1ea8851")
            ignore("00000000-0000-0000-ffff-ffffd1ea8851")
            ignore("00000000-0000-0000-ffff-ffffd1ea8851")
            ignore("00000000-0000-0000-0000-000040c768d1")
            ignore("00000000-0000-0000-0000-00007b51a185")
            ignore("00000000-0000-0000-0000-000071e611a7")
            ignore("00000000-0000-0000-0000-00001e1131a2")
            ignore("00000000-0000-0000-ffff-ffff8342a072")

            /** We ignore that ambiguous information may not be perfectly resolved. */
            ignore("00000000-0000-0000-ffff-ffffa2a5e9d0")
            ignore("00000000-0000-0000-0000-000062ff20fb")

            ignore("00000000-0000-0000-ffff-ffffdb1bac22")
            // We assume that the last VariableDeclaration in the statement kept in "variable" is
            // the variable we care about in the ForEachStatement if there is no
            // DeclarationStatement related to ffffffff-bc1f-6f40-ffff-ffffe99e3aad.
            //
            // To verify this assumption, we need to check if the last VariableDeclaration of the
            // variable is indeed the one where we assign the iterable's elements to.
            ignore("00000000-0000-0000-0000-0000112daa4c")
            // We assume that the last VariableDeclaration in the statement kept in "variable" is
            // the variable we care about in the ForEachStatement if there is no
            // DeclarationStatement related to ffffffff-bc1f-6f40-0000-000021ee9f9d.
            //
            // To verify this assumption, we need to check if the last VariableDeclaration of the
            // variable is indeed the one where we assign the iterable's elements to.

            /**
             * We assume that the list of endpoints that do not require authentication is exhaustive
             * and does not contain too many elements.
             *
             * To validate this assumption, it is necessary to check if this list is in accordance
             * with the documentation provided.
             */
            undecided("00000000-0000-0000-ffff-ffff82ebc975")

            /**
             * We assume that there exists a data flow from a method that performs a database access
             * (e.g., within an HTTP endpoint) to the `model_query` call expression represented by
             * this node.
             *
             * To verify this assumption, it is necessary to check the data flow.
             */
            undecided("00000000-0000-0000-0000-00005c26e6ab")

            /**
             * We assume that the `earlyTermination` is correct and that no more exception will be
             * thrown outside the function where the domain scope check is performed.
             */
            accept("00000000-0000-0000-ffff-ffffe3ff4474")
        }
    }
}

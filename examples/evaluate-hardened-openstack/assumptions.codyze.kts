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
            ignore("00000000-0000-0000-0000-00000704441f")
            ignore("00000000-0000-0000-ffff-ffff8a0075e1")
            ignore("00000000-0000-0000-0000-00003b218728")
            ignore("00000000-0000-0000-ffff-ffffc57fd8aa")
            ignore("00000000-0000-0000-ffff-ffff858bb3d4")
            ignore("00000000-0000-0000-ffff-ffffb6e331e9")
            ignore("00000000-0000-0000-0000-00003dea3c3c")
            ignore("00000000-0000-0000-ffff-ffffe35c3b77")
            ignore("00000000-0000-0000-0000-00002a6a541f")

            /** We ignore that ambiguous information may not be perfectly resolved. */
            ignore("00000000-0000-0000-ffff-ffffa2a5e9d0")
            ignore("00000000-0000-0000-0000-000062ff20fb")

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

            /**
             * We assume that the last variable in the list of variables is the one that is
             * important.
             */
            accept {
                it.assumptionType == AssumptionType.AmbiguityAssumption &&
                    it.message.startsWith("We assume that the last VariableDeclaration")
            }
        }
    }
}

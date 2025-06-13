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
            undecided("00000000-0000-0000-ffff-ffff88d01ccd")
            undecided("00000000-0000-0000-0000-0000126c56a4")

            /** We accept that the inference starts in a record, namespace or translation unit. */
            accept("00000000-0000-0000-ffff-ffffa1fa084e")
            accept("00000000-0000-0000-ffff-ffffa1fa084e")
            accept("00000000-0000-0000-0000-00005bae5c76")
            accept("00000000-0000-0000-0000-00003c6caf0e")
            accept("00000000-0000-0000-0000-000077a7e176")
            accept("00000000-0000-0000-ffff-ffffd1ea8851")
            accept("00000000-0000-0000-ffff-ffffd1ea8851")
            accept("00000000-0000-0000-ffff-ffffd1ea8851")
            accept("00000000-0000-0000-ffff-ffffd1ea8851")
            accept("00000000-0000-0000-0000-000040c768d1")
            accept("00000000-0000-0000-0000-00007b51a185")
            accept("00000000-0000-0000-0000-000071e611a7")
            accept("00000000-0000-0000-0000-00001e1131a2")
            accept("00000000-0000-0000-ffff-ffff8342a072")

            /** We accept that ambiguous information may not be perfectly resolved. */
            accept("00000000-0000-0000-ffff-ffffa2a5e9d0")
            accept("00000000-0000-0000-0000-000062ff20fb")

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
        }
    }
}

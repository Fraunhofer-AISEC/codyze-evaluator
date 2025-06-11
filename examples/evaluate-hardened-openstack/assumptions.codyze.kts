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
            undecided("00000000-0000-0000-ffff-ffff86494112")
            undecided("00000000-0000-0000-0000-0000303445dd")
        }
    }
}

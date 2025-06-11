/*
 * This file is part of the OpenStack Checker
 */
package example

project {
    assumptions {
        decisions {
            reject("00000000-0000-0000-0000-000005e80cd3")
            reject("00000000-0000-0000-0000-00005cc4430f")
            reject("00000000-0000-0000-0000-000070dd1de8")
        }
    }
}

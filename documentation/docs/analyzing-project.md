# How to analyze your project

The Codyze Evaluator is a tool that helps you identify security issues in your TOE by analyzing the code
and checking it against a set of predefined queries.
This document describes how to use the Codyze Evaluator to analyze your project, how to structure an analysis project
and how to write those queries.

## Project Structure


An evaluation project for the Codyze Evaluator requires few files to be included in the project directory and allows to add further custom files:

    .                                   # Project root
    ├── build.gradle.kts                # The build file of your project.
    ├── project.codyze.kts              # The project file which defines the evaluation project. It is used to configure the Codyze Evaluator for the specific evaluation.
    ├── tagging.codyze.kts              # This file includes specific tagging logic for the evaluation project. It has to be written specifically for the TOE but may reuse existing concepts and operations and logic for tagging library functions.
    └── src/main/kotlin/...             # This directory contains the concrete instance of the Codyze Evaluator which is built using the gradle file. It also contains custom logic.
        ├── queries                     # This directory contains custom queries.
            ├── query1.kt               # This file contains one or multiple custom queries which are used in the requirements of the evaluation project. The filename can be aritrary but must end with `.kt`.
            └── query2.kt               # This file contains one or multiple custom queries which are used in the requirements of the evaluation project. The filename can be aritrary but must end with `.kt`.
        └── Main.kt                     # The main file of the evaluation project. It calls the script `project.codyze.kts` to run the Codyze Evaluator.

Most importantly, the project requires the build file, the project definition, and the main file.
The other files could be omitted and the contents could be integrated in the project file, but we recommend to keep them separate for better maintainability.

## Defining an analysis project

We provide a Domain-Specific Language (DSL) to define an analysis project.
This DSL is used to specify the components of the TOE (Target of Evaluation) and the requirements it has to satisfy.
It further allows to integrate the logic for tagging the code with concepts and operations, and to accept or reject assumptions.
In the following, we describe how to configure the analysis project using the DSL.

The project is defined in a file called `project.codyze.kts` which is then passed to the Codyze Evaluator.

The outer element is the `project` element which has a `name` and can contain the declarative blocks `tool`, `toe`, `requirements`, and `assumptions`.
```kotlin title="project.codyze.kts"
project {
    name = "This is the evaluation of some TOE"

    tool { ... }
  
    toe { ... }
  
    requirements { ... }
  
    assumptions { ... }
}
```

The `tool` block can be used to fine-tune the configuration of the Codyze Evaluator by registering additional passes or external libraries, among others.
The full list of options can be found in the documentation of the `TranslationConfiguration.Builder`.
An instance of this class can be accessed within this block.
An example of a `tool` block is:
```kotlin title="The tool description in project.codyze.kts"
tool {
    // Register additional passes
    registerPass<MyPass>()

    // Where can includes be found
    includePath("src/integrationTest/resources/example/src/third-party/mylib")

    // Should include be loaded?
    loadIncludes(true)
}
```

The `toe` block is used to specify the TOE and where its components can be found.
The information provided here are used to translate the TOE to the CPG.
The following example shows how to use this block:
```kotlin title="The TOE description in project.codyze.kts"
toe {
    // The name of the TOE
    name = "My Mock TOE"
    // The architecture of the TOE in terms of different components
    architecture {
        // The list of each component/module
        modules {
            // The first module. The parameter specifies the name of the module.
            // The information provided here is used to configure the CPG translation.
            module("module1") {
                // The directory defines where the module's code can be found. 
                directory = "src/module1"
                // All files in this directory should be included in the analysis.
                includeAll()
                // We want to exclude the tests from the analysis. 
                exclude("tests")
            }
        }
    }
}
```

The `requirements` block is used to specify the requirements the TOE has to satisfy.
Each `requirement` listed here has a name and can be checked by automatically running a query, a manual assessment, or a combination of both.
The manual assessment is specified by using the `manualAssessmentOf` function which requires a unique identifier as a parameter.
The documentation of the check itself is not specified here but in another file.
The automatic assessment is specified by using the `byQuery` function runs a check on the `TranslationResult` and must return a `QueryTree<Boolean>` object.
```kotlin title="The requirements description in project.codyze.kts"
requirements {
    
        requirement {
            // Each of the requirements has a name
            name = "Is Security Target Correctly specified"
            // The description can provide additional information about the requirement.
            description = "This requirement checks if the security target is correctly specified in the code. To verify this, the evaluator must check if there is a file provided which contains all information required by the class ASE for the EAL this TOE targets. Conformance is verified based on the common criteria."
            // The requirement is composed by exactly one statement.
            // In this case, we have to assess manually, if the requirement is satisfied, what is done by the `manualAssessmentOf` function.
            // This function must be configured with a unique identifier of the check to be performed.
            manualAssessmentOf("SEC-TARGET")
        }

        requirement {
            name = ""Good Encryption"
            description = "This requirement checks if the encryption is done correctly. It is fully automated."
            // This requirement is checked fully automatically by the query.
            // The lambda receives the translation result as object in `this` and must return a `Decision` object.
            // It uses the two helper functions `goodCryptoFunc` and `goodArgumentSize` which are part of the catalogue and return a `QueryTree<Boolean>` object.
            // The `decide` function is called on the `QueryTree<Boolean>` object to get the final `Decision` object by assessing the acceptance of assumptions.
            goodCryptoFunc().decide() and goodArgumentSize().decide()
        }
  
         requirement {
            name = "Hybrid Check"
            description = "This requirement is checked by a hybrid approach." +
                "The first part is checked by the query specified in the `query` function." +
                "The second part is checked manually by the `manualAssessmentOf` function."
            // Both parts are combined by the `and` operator which returns a Decision object.
            query().decide() and manualAssessmentOf("HYBRID")
         }
    }
```
The block `assumptions` is used to specify the assumptions which have to hold so that the analysis is meaningful.
It also allows to specify the state of the assumption (i.e., accepted, rejected, ignored, or undecided).
To do so, the functions `accept`, `reject`, `ignore`, and `undecided` can be called with the UUID of the respective assumption.
To list more assumptions for documentation purposes, the function `assumption` can be used.
Note that this assumption does not have to be accepted manually and won't be included in the analysis or translation result.
```kotlin title="The assumptions descriptions of project.codyze.kts"
assumptions {
    // Documentation of an additional assumption which has to hold and is accepted.
    assume { "We assume that everything is fine." }
    decisions {
        // Accept the assumption with the UUID "00000000-0000-0000-0000-000000000000" which is part of the CPG or the queries.
        accept("00000000-0000-0000-0000-000000000000")
        // Reject the assumption with the UUID "00000000-0000-0000-0000-000000000001" which is part of the CPG or the queries. 
        reject("00000000-0000-0000-0000-000000000001")
        // Nobody has decided on the assumption with the UUID "00000000-0000-0000-0000-000000000002" which is part of the CPG or the queries.
        undecided("00000000-0000-0000-0000-000000000002")
        // Ignore the assumption with the UUID "00000000-0000-0000-0000-000000000003" which is part of the CPG or the queries.
        ignore("00000000-0000-0000-0000-000000000003")
    }
}
```
The decisions on the acceptance of the assumptions can also be moved into an own file, e.g., `assumptions.codyze.kts`, which can then be included in the project file using the `include` function as follows:
```kotlin title="project.codyze.kts"
include {
    AssumptionDecisions from "assumptions.codyze.kts"
}
```
```kotlin title="assumptions.codyze.kts"
project {
    assumptions {
        decisions {
            accept("00000000-0000-0000-0000-000000000000")
            reject("00000000-0000-0000-0000-000000000001")
            undecided("00000000-0000-0000-0000-000000000002")
            ignore("00000000-0000-0000-0000-000000000003")
        }
    }
}
```

Incorporating results of manual assessments is possible by documenting the results in a separate file, e.g., `manual.codyze.kts`, and including it in the project file:
```kotlin title="project.codyze.kts"
include {
    ManualAssessment from "manual.codyze.kts"
}
```
The `manualAssessment` block contains the assessments of the checks which are performed manually.
Each check is identified by a unique identifier, which is used to link the manual assessment to the requirement and is passed as a string parameter to the function `of`.
```kotlin title="manual.codyze.kts"
project {
    manualAssessment {
        // Document the manual assessment of check with identifier "SEC-TARGET".
        of("SEC-TARGET") {
            // The result of the manual assessment can be returned as a `Decision` object, `Boolean` or `QueryTree<Boolean>`.
            // When returning a `Decision` object, the acceptance of assumptions is considered, when returning a `QueryTree<Boolean>`, it is possible to add assumptions by calling the function `assume`.
            true
        }
    }
}
```

## Writing Security Requirements and Queries

The requirements are written in the `project.codyze.kts` file as described above.
All requirements which are (partially) checked by queries can call functions which are defined elsewhere in the project.
A common place to define those functions is the `src/main/kotlin/.../queries` directory.
The queries are written in Kotlin and can use the Query API to access the CPG and perform checks on it.
There are no specific restrictions on how to write them, but the result must be a `QueryTree<Boolean>`, `Boolean` or `Decision` object.

To increase the reusability of existing queries, it is advisable to split them up into small pieces of reusable code and externalize project-specific logic into own functions or variables.
This simplifies adapting the queries across different evaluation projects, or react to changes in the state of the art.

To write those queries, you should be familiar with the Kotlin programming language and the CPG's structure and Query API.
A set of initial resources could be:

* [Documentation of the Query API](https://fraunhofer-aisec.github.io/cpg/GettingStarted/query/). Note that you have to
  use the "extended" version here
* [The CPG's shortcuts](https://fraunhofer-aisec.github.io/cpg/GettingStarted/shortcuts/). These can be useful to
  quickly access interesting properties of the program under test.
* [The Kotlin Language Documentation](https://kotlinlang.org/docs/home.html). This is the official documentation of the
  Kotlin programming language. It lists all features of the language with various examples. The section "Concepts"
  should be the most relevant one.

The files [list-concepts-and-operations.md](list-concepts-and-operations.md), [writing-queries.md](writing-queries.md), and [more-resources.md](more-resources.md) provide further documentation on existing concepts and operations, writing queries with the Query API, and point to additional resources.
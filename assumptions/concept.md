# Categorization of Analysis Assumptions

Durin the analysis of a program, different limitations and problems appear. Assumptions are necessary to provide any results but are often not reported as part of the analysis result. This document is an initial idea on how to categorize assumptions, that can be added to the translation of a CPG, and finally collected and reported along with the results of a query.

## Assumptions on code completeness and availability
 - Code that is missing
 - Missing macros definition: We have to assume that it is a closed subtree in the AST
 - Ambiguities
 - Languages that cannot be analyzed
 
## Assumptions on language semantics and syntactic correctness
 - Ambiguities, we have them here too, although they are related to code completeness 
 - Warnings when we make nodes after finding a parser output that we did not expect.

## Assumptions on soundness and completeness
 - If the same flow is at some point not sound and at some point not correct it is relaxed to a general approximation

## Assumptions on data and control flow, approximations
 - Try statements and their disruption of CF
 - Assumptions on external input or labeling that an input is external
 - Assumptions on a config data point. Assumptions is e.g., that configs are save, cannot be injected

## Assumptions on runtime preconditions
 - Resource assumptions: the File, that is opened here, exists; network connection is available; DB runs and is reachable.
 - Assumptions on the platform or the execution environment, e.g. runs on Linux, etc.
 - Assuming one behavior over another when our CPG representation does not contain or cannot know behavioral differences at runtime, e.g., different platform or execution environment.

## Assumptions on sequentiality under parallel execution
 - Assumption that a critical section is atomic, e.g. that the execution of a line of statements is not disrupted by other threads.
 - Just whether or not we assume that execution is sequential or if we know there is some parallel execution, and we assume that it does not influence sequentiality when reading data.

## Assumptions on input data
 - Assumption on Entry Points(Or Endpoints): Data coming from here is external to the application. 
 - Data ranges on input that can be annotated
 - Assumption that data is trusted input
 
## Problems and Limitations

Problems and limitations during analysis influence how trustworthy results of an evaluation can be. As such they should be reported to the user when they influence his queries. This is the same motivation we have with assumptions, and we therefore plan to make them part of the same feature. However, strictly speaking they are different from assumptions.

Two solutions are possible in the categorization sense: 
 1. Problems and limitations are on the same level as assumptions:
   Categories:
  
    - Problems
    - Limitations
    - Assumptions
      - MissingCodeAssumptions
      - SyntacticCorrectnessAssumption
      - ...
   
 2. Or can we restate Problems and Limitations as Assumptions?
    - Assumptions
      - CanNotTranslateProblem as Assumption: We assume that the remainder of the query is not impacted by this problem.

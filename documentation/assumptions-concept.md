# Categorization of Analysis Assumptions

During the analysis of a program, different limitations and problems can appear. Assumptions are necessary to provide any results, but are often not reported as part of the analysis result. This document is an initial idea on how to categorize assumptions, that can be added to the translation of a CPG, and finally collected and reported along with the results of a query.

The purpose of categorizing assumptions is to reduce the mental load on the user who has to work with the analysis results and contained assumptions. Instead of unrelated assumption messages in a general assumption object, assumption categories allow a user to group assumptions when working with the results and make a quicker decision on the reliability of results based on the types of assumptions that are reported.

## Assumptions are Added ...

 - As Nodes to the Graph provided as meta information in .yaml.
 - As Nodes to the Graph during regular translation.
 - In the result, if a node with assumption was considered in a query.
 - In the result, if a query specifies that it makes assumptions.
 - In the result, if an analysis function in a query makes assumptions.

## Assumption Node Placement
Assumptions are added as overlay nodes connected to a graph node.

- When assumptions are added to the graph during translation, they are added to a node provided by the developer.
- When added over the .yaml, a heuristic decides what node is the node of reference.
  - If no node is identifiable, the assumption most likely has a global scope and is added to the translation result.
  - If we allow providing a code location or region.
    - In case a single location is provided, the assumption is placed at the largest node starting at that location.
    - If a region is provided, the assumption is placed at the largest encapsulating location. 

## Developers can Manually add Assumptions
 - During translation: `assume(ASSUMPTION_TYPE, NODE, SCOPE(LOCAL|GLOBAL), MESSAGE)`
 - As consideration of a Query through the returned QueryTree object: `queryTree.addAssumption(ASSUMPTION_TYPE, SCOPE(LOCAL|GLOBAL), MESSAGE)`

## Assumption Collection
Assumptions placed at CPG nodes are collected during evaluations that return a `QueryTree` object and placed in the `QueryTree` object. Assumptions are collected from nodes that are visited by the query tree evaluation or are attached to the AST-Ancestor of a visited node. Global assumptions are always included and summarized in the final result.

When a `QueryTree` is returned as a result, it is printed into a SARIF output. The assumptions are placed in the same SARIF output for later printing to the end user. Assumptions are placed as attachment objects to the SARIF output.
  
  - description: The assumptions message and the scope.
  - location: The file of the identified assumption or a path if the assumption was placed on a higher level, e.g., global or component.
  - region: the code region of the associated node, or nothing if the location is a path instead of a file.
  - rectangle: unused.

## Assumption Categories

### Assumptions on Analysis Completeness and Code Availability

*InferenceAssumption*, *ClosedMacroAssumption*, *UnsupportedLanguageProblem*, *MissingCodeProblem*, ...

Examples:
 - Missing code
 - Missing macros definitions: We have to assume that it is a closed subtree in the AST
 - Ambiguities
 - Languages that cannot be analyzed
 
### Assumptions on Language Semantics and Syntactic Correctness
*AmbiguityAssumption*, ...

Examples:
 - Ambiguities, can be result of incomplete code (see above) or insufficient parser complexity.
   - e.g. Assuming the expressions `a(b)` is a call to function `a` with argument `b` and not a cast of `b` to type `a`. 
 - Warnings when we make nodes after finding a parser output that we did not expect.

### Assumptions on Program Semantics

*ConceptPlacementAssumption*, *ExhaustiveEnumerationAssumption*, ...

An assumption that we correctly captured a program semantic, e.g. logging of data, crossing system boundaries, file operations.

 - When we place concepts in the graph, we assume that we correctly identified all necessary places.
 - When we check for white and blacklists in a query, we assume that these lists are complete.

### Assumptions on Soundness and Completeness

*CompletenessAssumption*, *SoundnessAssumption*, ...

Examples:
 - If the same flow is at some point not sound and at some point not correct, it is relaxed to a general approximation

### Assumptions on Data and Control Flow Approximations
*CFIntegrityAssumption*, *NoExceptionsAssumption*, *CFAllOrNothingExecutesAssumption*, *TrustedConfigAssumption*, *ExternalDataAssumption*, ...

Examples:
 - Try statements and their disruption of control flow
 - Assumptions on external input or labeling that an input is external
 - Assumptions on a config data point. Assumptions is e.g., that configs are saved, cannot be injected

### Assumptions on Runtime Preconditions
*NetworkAvailableAssumption*, *ResourceExistsAssumption*, *ServiceReachableAssumption*, ...

Examples:
 - Resource assumptions: the file, that is opened here, exists; network connection is available; the database runs and is reachable.
 - Assumptions on the platform or the execution environment, e.g. runs on Linux, etc.
 - Assuming one behavior over another when our CPG representation does not contain or cannot know behavioral differences at runtime, e.g., different platform or execution environment.

### Assumptions on Sequentiality under Parallel Execution
*AtomicExecutionAssumption*, ... 

Examples:
 - Assumption that a critical section is atomic, e.g. that the execution of a line of statements is not disrupted by other threads.
 - Just whether we assume that execution is sequential or if we know there is some parallel execution, and we assume that it does not influence sequentiality when reading data.

### Assumptions on Input Data
*TrustBoundaryAssumption*, *DataRangeAssumption*, *TrustedInputAssumption*, ...

Examples:
 - Assumption on entry points (or endpoints): Data coming from here are external to the application.
 - Data ranges on input that can be specified.
 - Assumption that data is trusted input.
 
### Problems and Limitations

Problems and limitations during analysis influence how trustworthy results of an evaluation can be. As such they should be reported to the user when they influence the queries. This is the same motivation we have with assumptions, and we therefore plan to make them part of the same feature. However, strictly speaking they are different from assumptions.

Two solutions are possible in the categorization sense: 
 1. Problems and limitations are on the same level as assumptions:
   Categories:
  
    - Problems
    - Limitations
    - Assumptions
      - MissingCodeAssumptions
      - SyntacticCorrectnessAssumption
      - ...
   
 2. Or can we restate problems and limitations as assumptions?
    - Assumptions
      - CanNotTranslateProblem as assumption: We assume that the remainder of the query is not impacted by this problem.

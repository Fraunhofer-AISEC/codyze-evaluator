# Interpretation of the results

After having ran the openstack-checker, you will find a file called `findings.sarif` in your current directory.
This file contains all results of the analysis in the [Static Analysis Results Interchange Format (SARIF)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).
SARIF aims to provide a standardized format for static analysis results, which can be used by different tools and platforms.
It is a JSON-based format that can be easily parsed and processed by various tools but is not really intended to by read by a human evaluator/analyst.

To simplify the interpretation of the results for a human, various ways to visualize the results are available:

* Plugins for IDEs
* Integration in CI/CD pipelines (e.g. on GitHub)
* The Web-UI of the openstack-checker

## Example IDE Plugin: Visual Studio Code

One example for a plugin that can be used to visualize SARIF results is the [SARIF Viewer](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer) for Visual Studio Code.
It can be installed from the marketplace and allows to open SARIF files directly in the IDE.

To use this feature, please follow these steps:

1. Install Visual Studio Code if you haven't already.
2. Install the SARIF Viewer extension from the Visual Studio Code marketplace if you haven't already.
3. Run the openstack-checker as described in the [README](../../README.md).
4. Copy the `findings.sarif` file to the directory of the codebase you analyzed. E.g. this could be the directory `./external` or `./projects/BYOK` or `./projects/magnum-cve`.
5. Now, open Visual Studio Code and open the directory containing the codebase and the SARIF-file. In the navigation bar on the left, you should see a file `findings.sarif`.
6. Open the file `findings.sarif` by double-clicking. Instead of the JSON representation of the file, you should now see a nicely formatted view of the results.

The findings are grouped by the location (i.e., the files containing the findings) or by the rules (i.e., the queries that found the findings).
The blue exclamation mark in front of the finding indicates that the query "passed", i.e., there is no violation against the desired security goal.
A red cross, in turn, indicates a violation.

By clicking on the finding, you can display more information on the rule which was evaluated, most importantly these are:

* The rule ID and name
* A description of the rule. Currently, this is the text of the statement.
* The "kind" (pass or fail)

In the tab "Analysis Steps", you can see the steps that were taken to evaluate the rule.
This allows to check the reasoning behind the result and follow all steps of the openstack-checker manually.
By clicking on the individual items in the list, you can get highlighting of the code considered in the step.

## The Web-UI

To avoid installing separate tools, the openstack-checker comes with its own Web-UI which allows to visualize the results.
To use the Web-UI, please run the analysis with the `--console=true` as indicated in the [README](../../README.md).
This will start a web server on your local machine which can be accessed via the URL `http://localhost:8080` once the analysis has finished.
Open this URL in your browser, and you should see a sections containing the Findings at the bottom of the page.
Each finding has its "kind" (pass or fail), the rule and the location of the finding.
You can click on the path and scroll to the indicated line to see where the starting point of the query was.
Currently, there is no support to show the whole analysis steps.

## Currently supported fields

The SARIF standard defines numerous fields that can be used to describe the results of a static analysis.
For a full list, we kindly refer to its [OASIS standard](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).
The openstack-checker currently only exploits a subset of all available fields.
Note that this may be subject to change in the future.

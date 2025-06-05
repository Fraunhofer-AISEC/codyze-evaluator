# Integration into Evaluation Processes on the Example of Common Criteria

The Codyze Evaluator may be integrated into existing evaluation processes which currently rely on manual documentation and code reviews.
An example for such a process is the Common Criteria (CC) Evaluation, which is a widely used standard for evaluating the security of IT products.

As mentioned above, in the scenario of a CC evaluation, two main sources can be used to extract the security goals:

* The Protection Profile to which the TOE claims compliance.
* The Security Target of the TOE, in particular the Security Functional Requirements (SFRs) and the details on their implementation.
  Obviously, if compliance to certain standards is claimed, the respective standards should also be used to derive the Codyze Evaluator Configuration.

Once a catalogue of security goals has been derived, the evaluator may simply select the applicable goals for the product.

In addition to the selection of the correct security goals, the tagging of the code with concepts and operations is a main task during the evaluation process.
Currently, the vendor/developer of the product needs to describe the security features and how they are implemented in the code.
This makes the Product Expert, who may be part of the development team, the ideal candidate for this task.
Rather than writing a document, the product expert can provide the tagging logic of the code with concepts and operations.
The evaluator would then review the tagging logic.

The Codyze Evaluator can then be used to check the compliance of the TOE's instance with respect to the security goals and thus assess if they hold.
This may reduce the need for extensive description and documentation of development processes and implementation details and how they are beneficial to fulfill the security goals in the product.
Instead, the Codyze Evaluator could be used to check the implementation of the security goals and provide a detailed report on the findings.

Certain mandatory aspects of the CC can be covered by the `project.codyze.kts` file.
In particular, it enforces specifying high-level information, the (security-)requirements which have to be fulfilled, and the architecture (in terms of modules) of the product.
It would, however, also be possible to extend the Codyze Evaluator to support additional mandatory aspects of the CC and thus provide an automated check if all required information is provided.
By providing Concepts and Operations representing certain aspects which have to be described during a CC evaluation, the Codyze Evaluator may even reduce the need for manual documentation of the product and could automatically check if the documentation (in terms of the tagging logic) is in-line with the product..
Examples for this include but are not limited to internal and external interfaces of the modules and product, or the security features of the product with their technical description.

Since the whole source code is required, this also fulfills the requirement of ADV_IMP.

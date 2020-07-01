# capa rules
Standard collection of rules for [capa](https://ghe.eng.fireeye.com/FLARE/capa): the tool for enumerating the capabilities of programs.

# philosophy
We want rule writing to be easy and fun! A larger rule corpus benefits everyone in the community and we encourage all kinds of contributions. If you have improvement ideas or encounter any issues, please let us know.

# rule nursery
The rule [nursery](https://github.com/fireeye/capa-rules/tree/master/nursery) is a staging ground for rules that are not quite polished. Nursery rule logic should still be solid, though metadata may be incomplete. For example, rules that miss a public example of the technique.

The rule engine matches regularly on nursery rules. However, our rule linter only enumerates missing rule data, but will not fail the CI build, because its understood that the rule is incomplete.

We encourage contributors to create rules in the nursery, and hope that the community will work to "graduate" the rule once things are acceptable.

Examples of things that would place a rule into the nursery:
  - no real world examples
  - missing categorization
  - (maybe) questions about fidelity (e.g. RC4 PRNG)

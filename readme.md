Most rules fit into an `$objective/$behavior/$technique` taxonomy.
This is specified via the `rule.meta.rule-category` field.
By convention, we organize the rule files into a directory structure that mirrors this taxonomy.
For example, the rule [send-data-on-socket.yml](./communication/communication-via-socket/send-data/send-data-on-socket.yml)
 is found in the directory 
 [communication](./communication/) /
 [communication-via-socket](./communication/communication-via-socket/) /
 [send-data](./communication/communication-via-socket/send-data/)
 that also matches the rule category.

Other directories here:

  - [maec](./maec/) - rules that match a sample's "disposition" and "role", which are specified via MAEC vocabularies:
    - disposition: [analysis-conclusion-ov](./maec/analysis-conclusion/)
    - role: [malware-category-ov](./maec/malware-category/)
  - [other-features](./other-features/) - miscellaneous attributes of a sample, such as "embedded PE" or "resource section".


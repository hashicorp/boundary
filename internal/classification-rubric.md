# Classification Rubric

This is an initial set of guidelines to use
when deciding on the classification of
[fields for API/SDK resources](./adding-a-new-field-readme.md#add-new-fields-to-the-apisdk-resource-protobufs).
The classification is used when generating audit events
and will impact the content of the events.

Fields can be classified as `secret`, `sensitive`, or `public`.
If a field is not classified, it is treated as `secret`.
The classification is used by the
[filters/encrypt][encrypt] library
along with a configurable filter operation.
By default
fields classified as `secret` will be redacted,
fields classified as `sensitive` will be encrypted,
and fields classified as `public` will be left un-modified.
See the [filters/encrypt][encrypt] package for more details.

* **secret**: This classification should be used for any field that contains
    information like tokens, keys, passwords.
* **sensitive**: This classification should be used for any field that contains
    information like [personally identifiable information (PII)][PII], such as
    names of people, email addresses, etc.
* **public**: This classification should be use for any field that is not
    sensitive or secret.

Tag `@jimlambrt` and `@jefferai` in your PR if you are unsure about how to classify a field.

[encrypt]: https://github.com/hashicorp/go-eventlogger/tree/main/filters/encrypt#encrypt-package-
[PII]: https://en.wikipedia.org/wiki/Personal_data

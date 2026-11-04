# Public source release

This repository contains the owner-approved public source release. It runs locally in rules-only mode by default. Its source tree includes the app, synthetic fixtures, aggregate evaluation evidence, research scripts and reproduction instructions. The three selected application captures document the same layout with optional local models enabled. [Setup and evidence](README.md)

## Contents and review status

| Material | Public package policy |
| --- | --- |
| Original source and documentation | MIT covers the original source code and documentation that the owner is authorized to license. [MIT license](LICENSE) · [License scope](LICENSE.NOTICE.md) |
| Third-party software and visible icons | Dependency declarations retain their upstream terms. The package carries Lucide and applicable Feather notices. [Third-party notices](THIRD_PARTY_NOTICES.md) |
| Three synthetic fixture screenshots | The owner approved publication of the three screenshots, visible branding and implemented design. |
| Dataset and model evidence | Source attribution, aggregate evaluation, the protocol and the training/evaluation scripts are included. Per-message records, all trained weights, corpora and SQLite files stay in the private workspace. [Provenance](DATASET_PROVENANCE.md) · [Model distribution decisions](backend/models/distribution-phase6.json) |
| Historical captures and vector figures | Supplied references, duplicate captures and historical vectors requiring unresolved font attribution stay local. Phase 6 aggregate comparison and confusion-matrix PNGs are included. [Model evaluation](MODEL_EVALUATION.md) |

The manifest identifies the precise file bytes and their SHA-256 values. The package audit records its findings and the owner's publication approval. The manifest records the digest of the reviewed source ZIP. [File manifest](PUBLIC_RELEASE_MANIFEST.json) · [Package audit](PUBLIC_RELEASE_AUDIT.json)

The owner approved the MIT grant for original code and documentation and confirmed publication rights for the selected assets. [Local operation and security](SECURITY_AUDIT.md)

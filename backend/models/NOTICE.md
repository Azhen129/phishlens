# PhishLens trained artifact notice

The public model directories carry metadata about locally trained scikit-learn artifacts. The original weights stay in the private research workspace. Only use trusted local artifact files. Joblib deserialization can execute code.

Email training source: SpaPhish v5, Bustio-Martinez and coauthors (2026), DOI10.17632/hz2d6gz7pc.5, CC BY4.0. URL training source: PhiUSIIL, Arvind Prasad and Shalini Chandra (2024), UCI dataset967, DOI10.1016/j.cose.2023.103545, CC BY4.0. Full attribution, source URLs, license links and adaptation notices are in docs/ml/dataset-provenance.json and each model's metrics.json. Adaptations select subject/body or raw URL, relabel the UCI target, deduplicate/group, partition and train the documented linear estimators. Source-derived annotations and webpage features are excluded.

Dataset license notices are preserved. The project MIT grant covers authorized original code and documentation. Dataset materials retain their own terms. [License scope](../../LICENSE.NOTICE.md) No raw dataset, private application database or local backup is part of the model deliverables.

Each manifest includes the model artifact SHA-256, exact scikit-learn version, feature code/version, validation scope, corpus-conditioned metrics and language restrictions. Email predictions are supported only within the documented Spanish scope; URL predictions use hostname-only features and do not inspect destination content or verify safety.

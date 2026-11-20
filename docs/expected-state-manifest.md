# Expected-state manifest v1

Provide an explicit JSON file on the personal Mac:

```json
{
  "schema_version": 1,
  "managed_categories": ["brew_formula", "brew_cask"],
  "resources": [
    {"resource_id": "brew_formula:git", "category": "brew_formula", "attributes": {"installed": true}},
    {"resource_id": "brew_cask:visual-studio-code", "category": "brew_cask"}
  ]
}
```

Run `mac-watchdog compare --manifest /path/to/manifest.json` to compare the file with the local SQLite inventory. The command is read-only and does not run playbooks or change machine configuration.

Resource IDs must match the inventory identifiers (e.g. `app:<CFBundleIdentifier>`, `brew_formula:<name>`, `brew_cask:<name>`, `pkg_receipt:<receipt-id>`, `launchd:<scope>:label:<label>` or `launchd:<scope>:file:<basename>`, `macos:build`). Only categories explicitly in `managed_categories` participate. Attributes are optional, flat scalar metadata and compared only if specified. Expected resources not currently observed are called `not_observed` because incomplete/stale discovery is possible.

This v1 consumer deliberately does not infer expected resources from Ansible tasks, and no automated exporter is included yet. Only use manifest data you intend to classify as managed.

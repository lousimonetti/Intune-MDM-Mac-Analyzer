# Sample logs

Synthetic logs that exercise every parser and many detection rules. They are
**not** real device data — they exist so you can try the tool immediately and
so the test suite has fixtures.

```bash
python3 -m intune_analyzer --input samples --html report.html --open
```

Layout mirrors a typical collected bundle:

```
samples/
├── Intune/         IntuneMDMAgent / IntuneMDMDaemon logs (auth, policy, app, compliance)
├── SSOExtension/   Platform SSO / Enterprise SSO extension log (registration, PRT, config corruption)
├── system/         install.log (PackageKit install failure)
├── mdatp/          Defender health + install logs (unhealthy, RTP off, threat, install error)
├── autoupdate/     Microsoft AutoUpdate log (download failure, auto-update disabled)
└── office/         Office app log (activation failure, crash)
```

# High fidelity with low false-negative risk

## Intent

Turn a **noisy** detection into a **high-fidelity** one without deleting the attacker’s real path (false negative).

Noise is usually: wrong channel breadth, cmdline-only tokens, missing identity scope, or single-API alerts that are normal in cloud.

## Playbook

### 1. Write the behavior sentence

Bad: “Suspicious PowerShell”  
Good: “PowerShell process creation with `-EncodedCommand` / `-enc` on host telemetry (4688 or Sysmon 1)”

If you cannot write one clear sentence, the rule is not ready.

### 2. Separate data gap from detection FN

| Situation | Action |
|-----------|--------|
| Org lacks 4688 cmdline / Sysmon | Document data gap; add alternate channel or do not claim coverage |
| Telemetry exists but rule misses after tune | You introduced an FN — revert or add OR path |

### 3. Anchor on high-confidence selectors

Prefer:

- Process **basename** + technique flag (`certutil.exe` + `-encode`)
- Cloud `eventName` + **sensitive parameter** (`PassRole` + `roleArn`)
- Parent/child or API sequence (PassRole → CreateFunction)

Avoid as sole logic:

- Bare `EventCode=1` / “any powershell”
- Substring matches that appear in admin chat, tickets, or search tools’ command lines

### 4. Cut noise without cutting truth

| Lever | Use when | FN risk |
|-------|----------|---------|
| Require process Image/NewProcessName | LOLBin cmdline pollution | Low if basename correct |
| Macro OR classic+XML | Multi-TA orgs | Low — reduces FN |
| coalesce fields then filter | Mixed 4688/Sysmon | Low |
| Exception list (hosts/ARNs/CI roles) | Known-good automation | Medium if list too broad |
| Correlation / time join | High-volume single APIs | Medium — tune window |
| Threshold (count > N) | Only for burst behaviors | High — attackers go slow |
| Drop technique token | Never as first resort | Very high |

### 5. Cloud example (noisy → tighter)

Noisy:

```spl
index=cloudtrail (eventName="PassRole" OR eventName="CreateFunction" OR eventName="UpdateFunctionCode" OR eventName="RunInstances")
```

Problems: hardcodes `index=`; ORs unrelated compute; every PassRole/RunInstances fires.

Higher fidelity direction (portable):

```spl
(sourcetype=aws:cloudtrail OR sourcetype=aws:cloudtrail:*)
(eventName=PassRole OR eventName=CreateFunction OR eventName=UpdateFunctionCode)
| eval calling_arn=coalesce(userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn)
| eval passed_role=if(eventName="PassRole", 'requestParameters.roleArn', null())
| eval target_function=coalesce('responseElements.functionArn', 'requestParameters.functionName')
| stats values(eventName) as actions values(passed_role) as roles values(target_function) as functions by calling_arn
| where mvcount(actions) > 1 OR (isnotnull(roles) AND isnotnull(functions))
```

(Adjust join/stats to org IR needs; **verify dotted fields** via official CloudTrail docs + memory before shipping.)

Remove `index=`; keep sourcetype permutations in memory.

### 6. Host LOLBin example

Noisy: `CommandLine="*encode*"`  
Better: `proc="*certutil.exe" AND (cmd="*-encode*" OR cmd="*-urlcache*" OR cmd="*-decode*")`  
Plus `` `windows_security` `` for XML+classic.

### 7. Before/after gate

Always re-run:

1. Known-good sim or trusted sample `_raw` → must still hit  
2. Spot-check 24h baseline volume → should drop  
3. Update `false_positives` and exception guidance in YAML  

## Anti-patterns

- Allowlisting `*powershell*` or entire OU “because noisy”
- Thresholds that hide low-and-slow
- Removing XML or 4688 path “to simplify”
- Trusting detections.ai author blindly without field doc check
- Shipping correlation windows shorter than real attacker/ops lag

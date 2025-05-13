# Overview 
Golang has a very opinionated on its package manager that is good at [mitigating supply chain attacks](https://go.dev/blog/supply-chain).
- Builds are locked. A versions contents cannot be upgraded. 
- The version control system is the source of truth. 
- Building code doesn't execute it.

Even with these, there is potential for dependency upgrades to backdoor the software. Detecting backdoored code, without reviewing every little change to every dependency and dependency of a dependency is nearly impossible. Golang released [capslock](https://github.com/google/capslock) in order to combat this. The tool performs static analysis to detect powerful interactions with the system and the Golang runtime, such as calls to `exec()`, unsafe code, etc. For more on it, read [this](https://medium.com/eureka-engineering/what-are-your-go-dependencies-capable-of-an-introduction-to-capslock-b757833c9847) article.

By comparing the outputs between runs, it's possible to review new capabilities in the dependencies. This repository is a wrapper around capslock to review changes and output usable information for triaging the changes made to repos. Capslock does a few things by default that we don't like: 
- Comparison mode is only text and not JSON. So, it's not possible to perform analysis on this information. 
- Includes CAPS for code within the local packages. Since these are going through PR review, these don't need to have a dependency review.

This program can be used standalone or as part of CI to determine if a particular area of code needs to be changed.

## Usage

### Wormhole CI 
- Creates the capslock file necessary for CI. Adds the file to the proper location.
- Requirements:
    - Ensure that the node can be built locally with Golang. 
    - Golang, Python and Pip must be installed. 
    - GOBIN must be part of the path. 
- Execute:
    - `./execute_capslock.sh`

### Dockerized (Preferred) 
- Automatically downloads the Github repo for you and does the diff on the previous file. 
- Previous runs are stored in the `logs` folder. All that needs to be done is run the docker container and this will pull the previous run to compare against.
- Build container:
    - `docker build -t capslock-diff .`
- Run program:
    - `docker run -v ./logs:/logs capslock-diff`

### Standalone 
- The default mode is comparison. This requires two files to be provided.
- Parameters on `diff.py`
    - package:
        - The default package that should be ignored. 
        - This is to prevent flagging our own repository on capabilities.
        - On Wormhole, this is `github.com/certusone/wormhole/node`. 
    - old:
        - The old capabilities file to compare against. 
    - new:
        - The new capabilities file to compare against. 
    - standalone:
        - Run a capability scan against a single file. Just outputs the file contents and does no comparison. 
        - Specify the file under `old`. 
- Example usage of `standalone` mode:
    - `python3 diff.py --old ./wormhole_caps.json --new ./wormhole_caps2.json --package github.com/certusone/wormhole/node`
- To generate the JSON files, run the following command in the go package: 
    - capslock -output json > cap.json

## Interpreting the Output 
The *capabilities* of a package are best described on [capslock](https://github.com/google/capslock/blob/c9355aa2f9687c73c507b4edcaaec6ed929d9a03/docs/capabilities.md). Each one of these is assigned a *danger* level. Some are more dangerous than others. For instance, `CAPABILITY_SYSTEM_CALLS` means direct access to system calls.
  
Luckily, there are not too many occurences in the Wormhole repository so it should be low noise on changes.

Example output: 
```
=== NEW CAPABILITIES DETECTED ===

Package: github.com/gagliardetto/solana-go
--------------------------------------------------
  • CAPABILITY_ARBITRARY_EXECUTION (Danger Level: 10)
    Path: github.com/certusone/wormhole/node.init github.com/certusone/wormhole/node/cmd.init github.com/certusone/wormhole/node/cmd/ccq.init github.com/gagliardetto/solana-go.init filippo.io/edwards25519.init (*filippo.io/edwards25519.Point).SetBytes (*filippo.io/edwards25519/field.Element).Subtract (*filippo.io/edwards25519/field.Element).carryPropagate filippo.io/edwards25519/field.carryPropagate
    Location: edwards25519.go:67:38

Package: github.com/cosmos/cosmos-sdk/client
--------------------------------------------------
  • CAPABILITY_EXEC (Danger Level: 9)
    Path: github.com/certusone/wormhole/node.init github.com/certusone/wormhole/node/cmd.init github.com/certusone/wormhole/node/cmd/guardiand.init github.com/certusone/wormhole/node/pkg/wormconn.init github.com/cosmos/cosmos-sdk/client.init github.com/cosmos/cosmos-sdk/crypto/keyring.init github.com/99designs/keyring.init github.com/99designs/keyring.init#3 github.com/godbus/dbus.SessionBus github.com/godbus/dbus.SessionBusPrivate github.com/godbus/dbus.getSessionBusAddress github.com/godbus/dbus.getSessionBusPlatformAddress os/exec.Command
    Location: kwallet.go:24:27

  • CAPABILITY_MODIFY_SYSTEM_STATE (Danger Level: 4)
    Path: github.com/certusone/wormhole/node.init github.com/certusone/wormhole/node/cmd.init github.com/certusone/wormhole/node/cmd/guardiand.init github.com/certusone/wormhole/node/pkg/wormconn.init github.com/cosmos/cosmos-sdk/client.init github.com/cosmos/cosmos-sdk/crypto/keyring.init github.com/99designs/keyring.init github.com/99designs/keyring.init#3 github.com/godbus/dbus.SessionBus github.com/godbus/dbus.SessionBusPrivate github.com/godbus/dbus.getSessionBusAddress os.Setenv
    Location: kwallet.go:24:27

Package: github.com/ipfs/go-log/v2
--------------------------------------------------
  • CAPABILITY_OPERATING_SYSTEM (Danger Level: 4)
    Path: github.com/certusone/wormhole/node.init github.com/certusone/wormhole/node/cmd.init github.com/certusone/wormhole/node/cmd/ccq.init github.com/ipfs/go-log/v2.init github.com/ipfs/go-log/v2.init#1 github.com/ipfs/go-log/v2.SetupLogging (*go.uber.org/zap/zapcore.ioCore).With go.uber.org/zap/zapcore.addFields (go.uber.org/zap/zapcore.Field).AddTo go.uber.org/zap/zapcore.encodeStringer (*github.com/prometheus/prometheus/scrape.Target).String (*github.com/prometheus/prometheus/scrape.Target).URL (github.com/prometheus/prometheus/model/labels.Labels).Range github.com/prometheus/prometheus/config.Load$1 os.Expand os.getShellName
    Location: setup.go:19:14

  • CAPABILITY_UNANALYZED (Danger Level: 3)
    Path: github.com/certusone/wormhole/node.init github.com/certusone/wormhole/node/cmd.init github.com/certusone/wormhole/node/cmd/guardiand.init github.com/certusone/wormhole/node/pkg/txverifier.init github.com/ethereum/go-ethereum/core/types.init github.com/ethereum/go-ethereum/core/types.rlpHash (*sync.Pool).Get
    Location: block.go:36:26
```

The output above contains 4 pieces of information: 
- Capability 
- Danger level 
- Module path 
- File Location 

Analyze each one of the new changes for threats. First, consider the capability and the danger level of it. This gives you an idea about what the function has the potential to do on the system.
  
Next, review the *module path*. The path contains the function being used. In the case of the listed `CAPABILITY_MODIFY_SYSTEM_STATE`, this is setting an environment variable. This will also give you context on the usage of it. For instance, the `CAPABILITY_OPERATING_SYSTEM` appears to be used for logging information on prometheus.
  
In many cases, it will require a more thorough review of the code to ensure that nothing malicious is happening. Some of the capabilities are effectively *"I can't see any further - please go look for youself"*, such as `CAPABILITY_ARBITRARY_EXECUTION` and `CAPABILITY_CGO`. Since the entire path of the code is known and all of this code is open source, go to the repository to review what is happening yourself. It should be noted that only the first occurence of a capability within a function is reported. So, even if something looks benign in that future, it should still be reviewed.
  
Hopefully, it's simple to review and to see what's going on. The cgo, unsafe pointer and arbitrary execution items are hard to track down because they are misdirection by design. If it's an attack, obfuscation and misdirection are likely though; so, don't skip on going down the rabbit hole in these cases. 


## Improvements
### Diff Engine
This is using a custom diff engine. The `capslock` tool has its own diff engine but it cannot output to JSON and is overly verbose. 
  
Some work needs to be done in order to ensure it's not missing any changes in the code or showing the same item more than once. It's unsure if there's a perfect way to detect if something has just *changed* (moved on a line in a file) or been seriously modified.

### Automation 
- Create a cronjob with the Docker container that will run once every while to do checks.
    - Call `cron.sh` in the cronjob.
    - `7 * * * *` will run every hour on the 7 minute mark.

## Limitations 
- There are cases where the [CAPABILITY_UNANALYZED](https://github.com/google/capslock/blob/main/docs/capabilities.md#capability_unanalyzed) is output. This is because of a limitation in the flow analysis of the tool itself. 
    - Currently, I'm unsure *why* and *when* this occurs so it's hard to know the impact. 
    - The `-noisy` flag on capslock can be used to include output of unanalyzed functions but this is very noisy and thus not recommended.
- Only a single usage of a capability in a function will trigger the report. If a capability is used more than once, it will not be shown:
    - For instance, `os/exec` used 5 times will only show the first occurrence. 
    - This means that if a package with `exec` usage is compromised and an accepted risk, then additional occurrences of the `exec` won't be noted.
- Removal of code within this repo:
    - The goal is to only need to review capabilities from included packages. Detecting this is *tricky* since we have multiple local packages.
    - The detection of this isn't perfect. For instance, it will not detect callbacks correctly.

## WH CI integration 
1. Action runs the comparison script:
    - Used to see if there is anything *new* between the current and old capabilities. 
    - If nothing new, then continue. If something new, then block the merge. 
2. Require change to the file to be reviewed by an AR team member. 
    - Do we automatically *force* the change in the PR by adding a commit? 
    - Does it require US to manually change it in the repo *before* they can merge?
    - Can we force add mandatory reviewers with a Github Action if the Capslock file changes?
    - What are *collisions* on the updates? Would require sequential updates...

## CI Process
- Developers to run the tool locally to update the file. If the file doesn't match our look up, then fail it.
    - Store the file in `node/.capabilities.txt`.
- Add security reviewers as a CODEOWNER to that file to require a *review* on all changes. 
- Now, all PRs with the file update MUST be done by AR. 
- Process: 
    - Create GitHub action that pulls down our tool from the main repo.
    - Build the tool on the *currently* provided repo.
    - Get the file on the branch itself and on main.
    - Compare branch file to *generated* file. If they don't match, exit. If they do match, then continue.
        - Post a comment to the PR relating to this if it DOES fail. Link to this Hack tool or something like that.
        - Simple `git diff` should be enough for us here.
    - Compare *main* with *new* branch. Output the result to the Action console for reviewing later. 
        - Helpful for *diff checking*.
- Similar thing is done on protobuf:
    - https://github.com/wormhole-foundation/wormhole/blob/55c0c6412d97e1598ca509cd1073f77ac4656fb0/.github/workflows/build.yml#L307
- Steps:
    - Create capslock file.
    - Compare branch with generated.
    - Compare file with main. 
    - If different, then do a run of `capslock automation` script to output capabilities.
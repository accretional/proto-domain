# Initial Plan

Define ebnf grammars for canonically formatted Domain Names/HostNames/etc baesd on the types I've already defined in this repo. Use github.com/accretional/gluon. Validate each on many different examples. Run fuzzing on them too. Before we start the rest of the project we can to see if we can create small .ebnf grammars the fully represent these types/formats and use them for parsing and printing the structured representations.

I've defined a little service for resolving DNS from a grpc server, you can use that for validation with ana ctual impl using the golang dns resolver library

Make sure to carefully study gluon's codebase to understand the tools available to implement this. Use v2/ wherever possible; eamine git commit history to check freshness. it's mid migration

You can use AST-AST transformations to handle the conversion to fixedlength messages using GrammarDescriptorProto, then another AST-AST transformation back to a single node string format, I think.

Take notes throughout your work to hlep you EXTENSIVELY in docs/impl-notes.md. Track your progress FREQUENTLY in docs/progress-log.md, maybe even after every few tool calls/actions.

# Setup/Invariants

Make sure you create a setup.sh, build.sh, test.sh, and LET_IT_RIP.sh that contain all project setup scripts/commands used - NEVER build/test/run the code in this repo outside of these scripts, NEVER commit or push without running these either. Make them idempotent so that each build.sh can run setup.sh and skip things already set up, each test.sh can run build.sh, each LET_IT_RIP runs test.sh

Have LET_IT_RIP.sh run queries over the actual local grpc service to resolve localhost and accretional.com

use go 1.26.

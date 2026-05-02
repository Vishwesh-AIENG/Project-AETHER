# How To Use The AETHER Skills System

This guide explains the workflow for using these SKILL.md files when collaborating with Claude (or any LLM assistant) on AETHER implementation.

## The Problem These Skills Solve

When you ask an LLM to write code for a specialized domain — like ARM64 hypervisor implementation — the model will produce output even when its training on that specific topic is sparse or partially incorrect. The output looks confident and structurally plausible. But the magic numbers might be wrong, the bit fields might be inverted, the sequence of operations might violate hardware ordering requirements that aren't covered in the model's training data.

These skills exist to inject a calibrated dose of "what you don't know" into the model before it generates code. By stating explicitly which areas Claude has weak training on, and pointing at primary sources that must be consulted, the skill file forces a more careful, verification-oriented mode of operation.

## The Three-Stage Workflow

### Stage One: Human Reading

Before any AI involvement, you read the chapter of the README that you're about to implement. Then you read the corresponding SKILL.md. Then you acquire and read the listed primary sources, at least the sections marked as "must consult." This is non-optional. The skills are not a substitute for primary source reading — they are an index that tells you which primary sources matter.

For dense material like the ARM ARM, a chapter that touches Stage 2 translation might require you to read 50–100 pages of the architecture manual before you understand enough to specify what you want implemented.

### Stage Two: Specification With Claude

Once you understand the area, you start a Claude session. You begin by pasting the entire SKILL.md into the conversation as context. Then you describe specifically what you want to implement, with reference to specific sections of the primary sources you read in Stage One.

A good specification looks like: "I'm implementing the Stage 2 page table walker for AETHER. Per ARM ARM Section D5.5, Stage 2 uses a different descriptor format than Stage 1. I need a Rust function that takes an IPA and returns the corresponding PA, walking the Stage 2 tables anchored at VTTBR_EL2. Walk me through the design before writing code."

A bad specification looks like: "Write the Stage 2 translation code for AETHER."

### Stage Three: Code Generation And Verification

When Claude generates code, you verify each non-trivial claim against primary sources. The Verification Protocol section of each SKILL.md gives you the specific checks to run.

For systems software, this verification step is not optional. A bug in Stage 2 translation can result in one guest reading another guest's memory — a complete isolation failure that defeats the entire purpose of the project. You verify because the cost of a missed bug is total.

## What To Paste When

For a focused implementation session on a single chapter:
- Paste the relevant SKILL.md
- Paste the chapter text from the README
- Describe your specific implementation goal

For a code review session:
- Paste the relevant SKILL.md
- Paste the code being reviewed
- Ask Claude to walk through the Verification Protocol

For a design discussion that spans chapters:
- Paste SKILLS_INDEX.md and CLAUDE_CONFIDENCE_MATRIX.md
- Paste the chapter texts you're discussing
- Frame the discussion as a design question

For research questions about an area Claude is weak in:
- Paste the SKILL.md
- Ask Claude to explain its understanding
- Cross-reference Claude's answer against the primary sources before trusting it

## Updating Skills Over Time

These SKILL.md files are not static. As you discover specific failure modes — places where Claude confidently produced wrong output — add those failure modes to the "Common AI Mistakes" section of the relevant skill. As you find better reference implementations, add them to "Secondary Sources." As primary sources are revised, update the section references.

The skills are a living knowledge base that improves as the project progresses. After two years of work, the skills should be substantially richer than they are at the start.

## What Skills Are Not

Skills are not a license to skip primary source reading. If a skill says "consult ARM ARM Section D5," the skill itself does not contain Section D5 — it points at it. You still have to read the section.

Skills are not a replacement for human expertise. They are a coordination mechanism that helps a human expert and an AI assistant work together effectively. Without the human expert in the loop, the skills cannot save you from systems-level bugs.

Skills are not a guarantee of correctness. Even with skills loaded, Claude can produce wrong output. The skills reduce the rate of confident-wrong output but do not eliminate it. Verification remains essential.

## When Skills Conflict With Each Other

If two skills give conflicting guidance, the more specific one wins. Chapter 8's SKILL.md is more authoritative for memory architecture questions than Chapter 11's SKILL.md, even if Chapter 11 mentions memory in passing. If a conflict is structural rather than detail-level, that indicates a flaw in the skills themselves and should be fixed in both files.

## When To Trust Claude Without Skills

For chapters marked HIGH confidence in the Confidence Matrix — basic Rust idioms, project management, build orchestration concepts — you can work with Claude without loading the SKILL.md as context, because Claude's training is solid in those areas.

For everything else, load the skill. The cost is a few thousand tokens of context. The benefit is dramatically reduced rate of subtle errors in the most safety-critical code in the project.

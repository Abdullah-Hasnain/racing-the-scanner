# Racing the Scanner: the 15-minute script

Generated from the speaker notes in `index.html` by `tools/build_script.py`; edit the notes, then rerun.
Planned: **14:20**. Estimated from the words at 140 words per minute: **14:19**.
Q&A and the appendix slides are not timed. Stage directions such as [click] are not counted.

| # | Slide | Presenter | Planned | Words | Est. | Cumulative |
|---|---|---|---|---|---|---|
| 1 | Operating Systems · Fall 2026: Racing the Scanner | M1 | 0:30 | 77 | 0:33 | 0:33 |
| 2 | Research question: Can an ML-augmented scheduler protect a memory sca… | M1 | 0:30 | 77 | 0:33 | 1:06 |
| 3 | Problem: A scanner sees hidden memory only while a page is… | M1 | 1:20 | 182 | 1:18 | 2:24 |
| 4 | Problem: A scan needs one eighth of the CPU; detection deli… | M1 | 1:25 | 211 | 1:30 | 3:54 |
| 5 | Hiding: Hiding cuts the catch rate to the time a page is e… | M1 | 1:30 | 204 | 1:27 | 5:22 |
| 6 | Simulation: Under mimicry all 14 ML policies miss 100% of wind… | M2 | 1:40 | 240 | 1:43 | 7:05 |
| 7 | Simulation: The disguised hog looks benign: 11 of 14 detectors… | M2 | 1:20 | 186 | 1:20 | 8:24 |
| 8 | Simulation: Reservations also cost 5.8× to 826× less policy co… | M2 | 0:55 | 122 | 0:52 | 9:17 |
| 9 | Real kernel: On real Linux 7.0 the hog slows EEVDF's scanner 9.… | M2 | 1:25 | 189 | 1:21 | 10:38 |
| 10 | Detection: One custom Tracee rule catches all 15 hiders with… | M3 | 1:25 | 201 | 1:26 | 12:04 |
| 11 | Conclusions: The kernel runs back the reservation half; the mim… | M3 | 1:10 | 161 | 1:09 | 13:13 |
| 12 | Conclusions: Don't try to win the detection arms race; sidestep… | M3 | 1:10 | 154 | 1:06 | 14:19 |
| 13 | References: References | - | not timed | - | - | - |
| 14 | Appendix A · Prior work: Two established lessons meet here, but not on a sc… | - | not timed | - | - | - |
| 15 | Appendix B · How we tested: A controlled comparison: one attack, four conditio… | - | not timed | - | - | - |
| 16 | Appendix C · The system: The scheduler sits between the attacker and three… | - | not timed | - | - | - |
| 17 | Appendix D · Simulation slowdown (G3): In simulation, starvation, not hiding, slows the s… | - | not timed | - | - | - |
| 18 | Appendix E · sched_ext: A sched_ext scheduler enforces a per‑process weigh… | - | not timed | - | - | - |
| 19 | Appendix F · Future work: Next: put the mimic against a real ML scheduler | - | not timed | - | - | - |

## 1. Operating Systems · Fall 2026: Racing the Scanner

*0:30 · Presenter: M1*

Good morning, everyone. We're Muhammad Abdullah Hasnain, Muhammad Abdullah Khan and Syed Ibad Asim, and our project is called Racing the Scanner. Our claim fits in one line: when an attacker disguises itself, a scheduler that tries to detect it loses, but a scheduler that simply reserves CPU for the defender doesn't. Over the next fifteen minutes we'll show you the evidence for both halves of that sentence.

> Transition: "Here is the question we set out to answer."

## 2. Research question: Can an ML-augmented scheduler protect a memory scanner from an attacker that hides its memory and hogs the CPU in disguise?

*0:30 · Presenter: M1*

Here's our research question in plain words: can an ML-augmented scheduler, one that uses machine learning to spot a suspicious process and slow it down, protect a memory scanner from an attacker that hides its memory and hogs the CPU while pretending to be a normal program? [click] We compare it with the simple alternative: a CPU reservation that guarantees the scanner its share without judging anyone.

> Transition: "To see why the CPU matters at all, here's the race."

## 3. Problem: A scanner sees hidden memory only while a page is exposed, so starving its CPU blinds it

*1:20 · Presenter: M1*

Malware scanners look inside a process's memory for a pattern they know is bad. On Linux, a live scanner can do that while the process is running, by reading /proc/pid/mem. The attacker's answer is to stop leaving its data in memory: it keeps it encoded or unmapped and exposes one page at a time, for a few milliseconds, only when it needs it. Those are the blue blocks. The top row is a scanner that runs every 37 milliseconds: eleven scans in 400 milliseconds, and two of them land inside a window, so it catches the attacker.

[click] Now the attacker adds a second trick. It runs a CPU hog on the same core at nice minus twenty, the highest priority in Linux's normal scheduling class. The scanner doesn't break. It just gets to run far less often: two scans in the same 400 milliseconds, and both miss.

[click] Hiding shrinks the target; starvation takes away the shots. So whether the scanner catches anything at all is really decided by the scheduler.

> Transition: "So which of the two defences keeps the scanner in the race?"

## 4. Problem: A scan needs one eighth of the CPU; detection delivers it only if it catches the hog

*1:25 · Presenter: M1*

Those are the two defences on the left. At the top, it can detect the hog and demote it: watch each process's timing, run a classifier, and cut the suspect's weight ten times. That's what our fourteen machine-learning policies do. Or, below it, the scheduler can simply reserve a share of the CPU for the scanner and never judge anyone. We tested five such reservations.

The chart shows why the choice matters. CPU is shared in proportion to weight, and a scan only finishes in time if the scanner gets at least one eighth of the CPU: the dashed line. With no attack, it gets 20 percent. With the hog running under stock Linux, it drops below 3. If an ML scheduler catches the hog, the scanner is back up to 22. If the ML scheduler is fooled, it only gets 5.6. And a reservation like cgroup cpu.weight guarantees 20, whatever else happens; every reservation we tested keeps the scanner above the line.

So everything hinges on one thing: does detection catch a hog that disguises its timing as a normal app? That disguise is called mimicry, and attackers have used it against intrusion detectors since at least 2002.

> Transition: "Before the schedulers, let's see how well hiding works on its own."

## 5. Hiding: Hiding cuts the catch rate to the time a page is exposed, at a steep cost, except for V4

*1:30 · Presenter: M1*

This is real hardware: an i7 running Linux 7.0, with the scanner and the payload pinned to one core. The bars are the share of scans that catch the payload, with a scan every 37 milliseconds, and the dashed line is the share of time a page is actually exposed. V2, which locks its pages with mprotect, follows that line almost exactly: 0.7 percent at a one-millisecond dwell, 25 percent at twenty-five. V3, which drops its pages with userfaultfd, is caught slightly more, because its pages stay exposed a few milliseconds longer. And V1, our control, is caught on every single scan.

On the right is the price. Hiding faults on every access, so V2 runs about 1,600 times slower than V1, and V3 about 2,200 times. V4 is different. It uses memfd_secret, which takes the memory off the kernel's direct map. It costs nothing, and not one of 806 scans caught it. So for V1 to V3, getting caught comes down to the scanner getting the CPU at the right moment: at a ten-millisecond dwell, each scan has roughly a one-in-ten chance, so the scanner needs to keep scanning. V4 we'll come back to at the end.

> Transition: "Over to M2 for the schedulers."

## 6. Simulation: Under mimicry all 14 ML policies miss 100% of windows; every reservation misses none

*1:40 · Presenter: M2*

To compare schedulers fairly, we built a simulation: one CPU shared by weight, the scanner, four benign apps and the hog, and twenty scheduling policies, each run twenty times. This is our main result, under the full attack with the disguised hog. Each bar is one policy's 95th-percentile scan latency, and the dashed line is the eight-tick window a scan has to finish inside. We use the 95th percentile so that a policy can't hide a tail of very late scans behind a good average.

In blue, the five reservations: all of them under the line, zero missed windows. A reservation here is a promise made in advance: for cgroup cpu.weight, a 25-to-100 split that guarantees the scanner 20 percent; for SCHED_DEADLINE, a budget of one fifth of every period. In orange, all fourteen machine-learning policies: they sit between 18 and 20.5 ticks, above the line, so they miss every single window, the same outcome as stock EEVDF at 35. That's the median of twenty runs; in a few individual runs, three of the detectors dip to between 78 and 98 percent, when a false positive happens to hit the hog.

And this isn't because the detectors are badly built. On the right: against a naive hog that doesn't disguise itself, the very same fourteen policies catch it perfectly, and the scanner misses nothing. It's the disguise, and only the disguise, that beats them.

> Transition: "So why can't they see it?"

## 7. Simulation: The disguised hog looks benign: 11 of 14 detectors score it at or below chance

*1:20 · Presenter: M2*

This chart is each detector's own score, its ROC-AUC, for telling the hog apart from the benign apps. 0.5 is a coin flip. Eleven of the fourteen are at or below chance, and the median is 0.285. Below chance means the detector actually thinks the hog looks more normal than the real applications. The two at 0.50, random forest and k-NN vote, simply call the mimic and the apps normal alike.

The sketch on the right shows why. Real apps each have their own jitter, so they spread out around typical behaviour. The mimic copies typical behaviour exactly, so it sits right in the middle: the least unusual process on the whole machine. A detector built to flag outliers will wave it straight through. The naive hog, by contrast, sits far out on its own, and every detector catches it.

The three supervised models that score slightly above chance still never demoted the mimic on a single tick. This is the same lesson the adversarial machine-learning literature keeps finding: a detector tuned to one attacker loses to an attacker that adapts.

> Transition: "Reservations also win on cost."

## 8. Simulation: Reservations also cost 5.8× to 826× less policy compute than the ML policies

*0:55 · Presenter: M2*

This is how much compute each policy spends per 600-tick run, on a log scale, counting both deciding what to do and actually allocating the CPU. The five reservations, in blue, spend between 2 and 8 milliseconds. The fourteen ML policies spend from 48 milliseconds up to 1.8 seconds for random forest. So a reservation is between 5.8 and 826 times cheaper. These are single-core Python timings, so a real kernel would pay far less for a reservation, close to nothing per decision. But the gap is the point, because a scheduler makes these decisions constantly, every tick, for every process: the policy that actually protects the scanner is also the cheap one.

> Transition: "Does any of this hold on a real kernel?"

## 9. Real kernel: On real Linux 7.0 the hog slows EEVDF's scanner 9.1×; a reservation holds it at 1.0×

*1:25 · Presenter: M2*

Back to real hardware, the same i7 on Linux 7.0, now with four CPU hogs at nice minus twenty sharing the scanner's core. The solid bars are the simulation; the hatched bars are the real kernel. Each bar is how much slower the scanner gets compared with no attack.

Hiding alone doesn't slow the scanner down anywhere. Starvation does: seven times in the simulation and 9.1 times on the real kernel, where stock EEVDF drops the scanner from about 27 scans a second to 2.95 and loses 89 percent of its scans. Under the combined attack it's 5.7 times. With a cgroup cpu.weight reservation, in blue, the scanner stays at 1.0 in every condition, and SCHED_FIFO does exactly the same. The scan itself never gets slower; the scanner is simply waiting for CPU.

We also checked that a kernel can enforce per-process weights the way our model assumes: a patched sched_ext scheduler, scx_qmap, holds them within 3.3 points of the model. One honest note: on hardware we tested the reservation half; we did not run the mimic against an ML scheduler.

> Transition: "Over to M3, on catching the hiders directly."

## 10. Detection: One custom Tracee rule catches all 15 hiders with no false alarms; the default rules catch none

*1:25 · Presenter: M3*

Scheduling decides when the RAM scanner runs, but V4 can't be seen by a RAM scanner at all. So we also watched system calls, with Tracee. Across five capture batches we ran 15 hiding processes and 30 benign ones: things like Node.js, Go and Java garbage collection, and SQLite, which use the same memory calls as the attacker.

Tracee's 27 default signatures caught none of the hiders and raised 5 false alarms. Our custom rule watches for one signal per payload, shown on the right: a memory region unlocked and then relocked at the same address for V2, any use of userfaultfd for V3, and any memfd_secret for V4. It caught all 15, including V4, with no false alarms. Why not simply flag every unlock from PROT_NONE? Because normal programs do that too: the detection runs report Node.js making 158 such flips and the JVM 1,413, without ever relocking a region the way V2 does. The default rules' 5 false alarms all came from our JIT stand-in, one per batch. We also gave the same features to a local language model; it caught 10 of 15 and took about 400 milliseconds per process.

> Transition: "Now, what this evidence does and doesn't show."

## 11. Conclusions: The kernel runs back the reservation half; the mimicry result rests on the simulation

*1:10 · Presenter: M3*

Here's an honest map of our evidence. Each row is a claim, each column is a testbed, and a filled mark means we tested that claim there. The reservation result holds in the simulation and on bare metal, and sched_ext confirms the kernel can enforce the weights, though in a VM with the penalty set by hand. The mimicry result, on the other hand, rests on the simulation: we never ran the mimic against an ML scheduler on real hardware. The detection result comes from 45 processes on one machine, with a workload mix we chose ourselves. And EEVDF's slowdown on hardware changed between two of our runs, for reasons we couldn't pin down. And two supporting observations, the Node.js and JVM flip counts I just mentioned and a control run with the hog at normal priority, come from captures we logged but didn't commit. Those are the limits to keep in mind when you weigh the result.

> Transition: "So, to conclude."

## 12. Conclusions: Don't try to win the detection arms race; sidestep it

*1:10 · Presenter: M3 · leave this slide up for Q&A*

Three takeaways. [click] One: detection loses to mimicry. All fourteen machine-learning policies miss every window, because the disguised hog looks benign. [click] Two: a CPU reservation sidesteps the problem entirely. Zero misses, far less compute, and it never has to classify anyone. [click] Three: the real kernel agrees. The hog slows stock EEVDF's scanner more than nine times, and a reservation holds it steady.

[click] And one thing surprised us. The reservation floor we designed turned out to be numerically identical to Linux's own cgroup cpu.weight and SCHED_DEADLINE. So the fix isn't a new mechanism; it already ships in the kernel. Our next steps would be to run the mimic against a real ML scheduler on bare metal, to build a sched_ext reservation for the scanner, and to widen the detection study to more workloads and machines. The lesson: don't try to win the detection arms race; sidestep it. Thank you, and we're happy to take your questions.

**Q&A backup (not timed)**

- If asked why we didn't train the detectors on the mimic: the mimic sits where benign behaviour is densest, so a better model of "normal" trusts it more; training on this mimic would just invite the next disguise [8], [9]. A reservation only needs to know which process is the scanner, which the defender controls.

- If asked whether the invariant is new: no. A 25:100 cpu.weight split and a 0.2 SCHED_DEADLINE budget give exactly its allocation in all 8 condition and attacker cells, asserted by the test suite.

- If asked about cpu.max: it is the only reservation that also contains the hog (benign apps keep 64% of the CPU), but it depends on the cap: at 40% per process the scanner misses 32% of windows, at 50% all of them.

- If asked why simulate: a model sweeps 20 policies reproducibly with no kernel or VM noise; the real-kernel runs then check the reservation half on hardware. Appendix slides A–F hold the details.

## 13. References: References

*0:00 · Not presented. IEEE numbered, matching the report.*

## 14. Appendix A · Prior work: Two established lessons meet here, but not on a scanner's CPU time

*0:00 · Appendix, for questions about related work.*

## 15. Appendix B · How we tested: A controlled comparison: one attack, four conditions, four testbeds

*0:00 · Appendix, for questions about method.*

## 16. Appendix C · The system: The scheduler sits between the attacker and three defenders

*0:00 · Appendix, for questions about how it was built.*

## 17. Appendix D · Simulation slowdown (G3): In simulation, starvation, not hiding, slows the scanner; ML barely helps under mimicry

*0:00 · Appendix, if asked how the ML policies slow down per condition.*

## 18. Appendix E · sched_ext: A sched_ext scheduler enforces a per‑process weight within 3.3 points of the model

*0:00 · Appendix, if asked about sched_ext.*

## 19. Appendix F · Future work: Next: put the mimic against a real ML scheduler

*0:00 · Appendix, if asked what comes next.*


# Locksport

## 🎯 Purpose
Comprehensive guide to locksport as a legitimate skill and competitive sport - covering mechanical lock theory, hands-on picking and impressioning techniques, tool selection, combination safe manipulation, and competition formats used at DEF CON, TOOOL, and ALOA events.

## ⚙️ Function
Organized in three parts: (I) Foundations - how locks work, what makes them secure, laws and community; (II) Techniques - pin tumbler picking, lever locks, impressioning, safe manipulation, advanced lock types, tools; (III) Competition - setup/hosting, strategy/tactics, competition formats and scoring.

## 🏆 Goal
Enable security professionals to understand physical security mechanisms at a hands-on level - both for offensive physical penetration testing and for evaluating the physical security posture of facilities being assessed.

## 📋 When to Use
- Physical penetration testing engagements requiring lock bypass skills
- Physical security assessments evaluating lock quality and resistance
- Locksport competition preparation (DEF CON Lockpicking Village, TOOOL, ALOA)
- Understanding physical access control as a complement to network security work

> **Scope:** The art, sport, and science of lock picking - covering mechanical lock fundamentals, hands-on picking and impressioning techniques, tool selection, and competitive locksport. This section treats lock picking as a legitimate skill and sport, consistent with the laws and ethics of the locksport community.

## 🎯 Purpose
Standalone reference on physical lock mechanics, picking/impressioning technique, and competitive locksport - the only file in this repo covering physical (non-cyber) security bypass in depth. Complements the Flipper Zero/hardware guides' brief NFC/RFID badge-cloning coverage but doesn't overlap with them: this is entirely about mechanical locks, not electronic access control.

## ⚙️ Function
Three parts: foundational lock mechanics and legal landscape (Part I), hands-on picking/impressioning/safe-manipulation technique (Part II), and competitive locksport formats and strategy (Part III). Unlike the tool-focused Documentation files, this one is almost entirely technique and physics - there's no firmware, no CLI, no version drift to track.

## 🏆 Goal
Understand how mechanical locks work well enough to evaluate their security, pick a pin-tumbler lock via single-pin-picking, and know the legal/ethical boundaries of practicing and competing in locksport.

## 📋 When to Use
- Physical security assessments where lock/access-control mechanisms are in scope
- Learning locksport as a hobby or preparing for competition
- Reference for lock terminology and security-pin behavior when picking is part of a physical penetration test

---

## Table of Contents

- [Part I: Locksport Foundations](#part-i-locksport-foundations)
  - [Chapter 1: How Locks Work](#chapter-1-how-locks-work)
  - [Chapter 2: What Makes a Lock Secure](#chapter-2-what-makes-a-lock-secure)
  - [Chapter 3: Laws, Competitions, and Community](#chapter-3-laws-competitions-and-community)
- [Part II: Hands-On Techniques](#part-ii-hands-on-techniques)
  - [Chapter 4: Pin Tumbler Picking](#chapter-4-pin-tumbler-picking)
  - [Chapter 5: Lever Locks](#chapter-5-lever-locks)
  - [Chapter 6: Impressioning and Key Crafting](#chapter-6-impressioning-and-key-crafting)
  - [Chapter 7: Combination Safe Manipulation](#chapter-7-combination-safe-manipulation)
  - [Chapter 8: Tools of the Trade](#chapter-8-tools-of-the-trade)
  - [Chapter 9: Advanced Lock Types](#chapter-9-advanced-lock-types)
- [Part III: Competition Insights](#part-iii-competition-insights)
  - [Chapter 10: Competition Setup and Hosting](#chapter-10-competition-setup-and-hosting)
  - [Chapter 11: Strategy, Nerves, and Lock Intel](#chapter-11-strategy-nerves-and-lock-intel)
  - [Chapter 12: Competition Formats](#chapter-12-competition-formats)

---

## Ethics and Legal Notice

Lock picking is a legitimate skill practiced by locksmiths, security professionals, hobbyists, and competitive athletes worldwide. The locksport community operates under a clear ethical framework:

**The Locksport Honor Code:**
- Only pick locks you own or have explicit permission to pick
- Never pick a lock that is in use securing property
- Never pick a lock you are not prepared to purchase as replacement (you may damage it)
- Share knowledge openly; support fellow sport pickers

**Legal context varies by jurisdiction** - see Chapter 3 for a detailed breakdown. In most US states and many countries, possession of lock picks is legal. Intent and context determine legality in ambiguous cases. When in doubt, consult local statute.

---

## Part I: Locksport Foundations

### Chapter 1: How Locks Work

#### The Core Problem Locks Solve

Every lock is a mechanical solution to a single problem: allowing authorized access while denying unauthorized access. Understanding the mechanism is the first step to evaluating - or defeating - it.

#### Pin Tumbler Locks

The most common lock type worldwide. Found in residential deadbolts, padlocks, file cabinets, and most everyday applications.

**Components:**

| Part | Function |
|------|----------|
| **Plug** | Rotating cylinder; contains the keyway; rotates when correct key is inserted |
| **Shell / Housing** | Outer body; holds the plug and driver pins in place |
| **Key pins (bottom pins)** | Contact the key; vary in height to match key bitting |
| **Driver pins (top pins)** | Spring-loaded; span the plug-shell gap to prevent rotation |
| **Springs** | Push driver pins down; maintain pressure on key pins |
| **Shear line** | The gap between plug and shell; all pins must align here to open |

**How it works:**

```
Without key (locked):
  Shell ──────────────────────
  Driver pins ▼▼▼▼▼ (span shear line - lock blocked)
  ─ ─ ─ ─ shear line ─ ─ ─ ─
  Key pins   █████
  Plug ───────────────────────

With correct key:
  Shell ──────────────────────
  Driver pins  ▼▼▼▼▼  (all sitting above shear line)
  ─ ─ ─ ─ shear line ─ ─ ─ ─  ← all gaps align here
  Key pins   █████  (lifted by key bitting to exact height)
  Plug ───────────────────────  ← plug can now rotate
```

The key's **bitting** - the pattern of cuts - lifts each key pin to a precise height so that every key-pin/driver-pin interface sits exactly at the shear line simultaneously.

**Pin count:** Most consumer locks use 5 pins. High-security locks use 6–7. More pins = more possible key combinations and more picking difficulty.

**Disassembly for practice:**

```
Tools needed: follower tool (same diameter as plug), plug follower block or pinning tray

1. Insert follower behind plug after removing cylinder from lock body
2. Push plug out forward with follower - follower maintains spring/driver pin position in shell
3. Tip plug: key pins will fall out (catch them - they're tiny)
4. Use a pick or pin to push driver pins and springs out of shell chambers
5. Sort and label pins by chamber number; document heights
6. Reverse to reassemble; use plug follower to re-engage drivers without losing them
```

**Practice lock recommendation:** Buy a transparent/cutaway lock (available on Amazon for $10–15) to watch pins set in real time. Also pick up 3–5 cheap Master Lock No. 3 or No. 140 padlocks for practice before moving to higher grades.

---

#### Wafer Locks

Found in filing cabinets, desk drawers, older vehicles, and low-security padlocks. Simpler than pin tumblers.

- Single-piece wafers span the plug-housing gap (unlike the two-piece pin tumbler stack)
- No springs in the traditional sense - wafers are flat spring steel
- More susceptible to raking and jiggling than pin tumblers
- Low pick resistance; useful for beginners to build feedback intuition

---

#### Lever Locks

Common in deadbolts (particularly European mortise locks), padlocks (especially British and older American designs), and safe deposit boxes. Dominant in UK and European security applications.

**Components:**

| Part | Function |
|------|----------|
| **Levers** | Multiple flat metal plates; each must be lifted to a precise height |
| **Post / Stump** | Fixed protrusion; blocks bolt movement unless lever is at correct height |
| **Bolt** | The locking bar; retracted when all levers align |
| **Curtain** | Metal shield blocking the keyhole from direct picking access |
| **Gating** | The notch in each lever that the post passes through when correctly lifted |

**How it works:** The correct key lifts each lever to the exact height where its gate aligns with the post. When all gates align, the post can pass through and the bolt retracts. Too low or too high on any lever = blocked.

---

#### Disc Detainer Locks

Common in Abus and Abloy products. Use rotating discs rather than pins or levers.

- Each disc has a notch; all notches must align to allow the sidebar to fall
- Require a specialized rotating pick rather than standard tension + lifting
- High-security variants (Abloy Protec2) are extremely pick-resistant
- Good cross-training for locksport - very different tactile feedback from pin tumblers

---

#### Combination Locks

Two main types: **padlock dials** (consumer) and **safe locks** (high-security).

**Consumer dial combination:**
- Three or four cams/discs with notches
- Dial controls rotation of cams through detent mechanisms
- When all notches align, a fence drops, releasing the shackle

**Safe combination locks:**
- Precision-machined; typically 3-wheel (100 positions each = 1,000,000 combinations)
- Relocking mechanisms, anti-drill plates, anti-manipulation features in high-security models
- Manipulation (non-destructive opening) is a key locksport and locksmith skill - covered in Chapter 7

---

#### Maintenance and Practice Lock Care

Keeping practice locks in good condition extends their life and improves feedback:

| Maintenance Task | Frequency | Method |
|-----------------|-----------|--------|
| Lubrication | Monthly (heavy use) or annually | Dry PTFE spray or graphite powder - **never WD-40** (petroleum-based; attracts dirt, degrades rubber) |
| Pin inspection | When feedback degrades | Disassemble; check for worn, burred, or corroded pins |
| Spring replacement | When springs feel weak or inconsistent | Source replacement springs from locksmith supply (Multiplex, Hudson) |
| Keyway cleaning | When grit is felt | Compressed air; soft brush; dry lube |
| Re-keying | When bitting is memorized | Rotate pins to create new combination; maintains practice value |

**Pin kit investment:** Buy a pinning kit (comes with assorted driver pins, key pins, springs, and a follower) from Peterson, Multiplex, or Sparrows. Being able to re-pin and rebuild locks is foundational locksport knowledge, not just a maintenance task.

---

### Chapter 2: What Makes a Lock Secure

Security is not binary. Locks exist on a spectrum defined by multiple factors. Understanding this spectrum lets you evaluate targets, select appropriate practice locks for skill building, and understand what the locksport ranking systems measure.

#### Security Factors

**1. Pin Count and Bitting Range**

More pins = exponentially more possible key combinations. Wider bitting depth range (more distinct cut depths) multiplies combinations further.

| Pins | Depths | Combinations |
|------|--------|-------------|
| 5 | 4 | 1,024 |
| 5 | 10 | 100,000 |
| 6 | 10 | 1,000,000 |
| 7 | 10 | 10,000,000 |

**2. Security Pins**

Standard driver pins are uniform cylinders - easy to set because the feedback is clear. Security pins are modified to provide false sets and resist picking. See Chapter 9 for detailed coverage.

| Pin Type | Description | Picking Difficulty |
|----------|-------------|-------------------|
| Standard | Uniform cylinder | Baseline |
| Spool pin | Hourglass profile; creates false set | Moderate |
| Serrated pin | Multiple false set positions per pin | High |
| Mushroom pin | Similar to spool; different profile | Moderate-High |
| T-pin | T-shaped; extremely tight false set | High |

**3. Keyway Design**

The keyway's shape restricts which pick profiles can enter. A complex, tightly toleranced keyway with many wards forces the use of narrow picks, reducing manipulation options and slowing picking.

**4. Tolerances and Manufacturing Quality**

High-quality machining means tighter tolerances between plug and shell. Tighter tolerances = less plug movement during picking = harder to feel pin states = slower attack. Budget locks often have loose tolerances that make picking trivially easy.

**5. Anti-Pick Features**

- **Sidebar:** A secondary locking mechanism (Medeco, Mul-T-Lock) requiring pins to also rotate to specific orientations - adds a second dimension of information required
- **Paracentric keyway:** Extremely convoluted profile; frustrates pick insertion
- **False gates:** Additional notches in lever lock gates; confuse manipulation
- **Security curtain:** Restricts physical access to lever lock internals

**6. Physical Attack Resistance**

| Attack | Relevant Lock Feature |
|--------|----------------------|
| Drilling | Hardened steel inserts, anti-drill pins |
| Cutting / sawing | Shackle hardness (Grade 5 steel vs. cheap alloys) |
| Shimming | Double-locking shackle mechanism |
| Bumping | Bump-resistant drivers, spool pins |
| Impressioning | Harder key blanks, restricted key profiles |
| Bypass | Anti-bypass plates, ball-bearing shackle |

#### Lock Grading Systems

**ANSI/BHMA (US residential):**

| Grade | Use | Cycle rating | Security |
|-------|-----|-------------|---------|
| Grade 1 | Commercial | 250,000 cycles | Highest residential |
| Grade 2 | Heavy residential | 150,000 cycles | Mid |
| Grade 3 | Residential | 100,000 cycles | Minimum |

**European EN 1303 / EN 12209:**
- Classes 1–6 for cylinders; Classes A–E for attack resistance
- Higher class = tested against progressively sophisticated attacks

**Sold Secure (UK):**
- Bronze / Silver / Gold / Diamond ratings
- Gold = suitable for securing motorcycles and high-value assets
- Diamond = highest grade; product-tested against power tools

**CMDTA / Master Keying Security:**
Security degrades in master key systems because pins must accommodate multiple valid keys - this creates predictable pin stack patterns that experienced pickers can exploit.

#### The Locksport Belt Ranking System

The locksport community (particularly /r/lockpicking and associated discord communities) uses a belt-ranking system analogous to martial arts:

| Belt | Typical Locks |
|------|--------------|
| White | Master Lock No. 3, basic padlocks |
| Yellow | Master Lock 140, American Lock 1100 |
| Orange | Master Lock 930, ABUS 55/40 |
| Green | Kwikset deadbolts, Master Lock Pro Series |
| Blue | Schlage B-series, ABUS 64TI |
| Purple | Medeco Biaxial, Mul-T-Lock MT5 |
| Red | ASSA Abloy Protec, Abloy Protec2 |
| Brown | Bowley Lock, Sargent & Greenleaf 833 |
| Black | DOM ix KG, EVVA 3KS |
| Red/Black | Reserved for exceptional achievements |

---

### Chapter 3: Laws, Competitions, and Community

#### Legal Landscape

**United States:**

Lock picks are legal to own in most US states. A small number of states have more restrictive statutes:

| State | Status | Notes |
|-------|--------|-------|
| Most states | Legal to own | No restrictions beyond intent |
| Virginia | Restricted | Possession with intent to commit burglary is the key statute; lawful possession for locksport is generally accepted |
| Ohio | Possession can be prima facie evidence | Context and intent critical |
| Nevada | Restricted | Possession is presumed for unlawful purposes unless rebutted |
| Mississippi | Some restrictions | Verify current statute |

> **Always verify current local law.** Statutes change. Being a known and active locksport hobbyist (community membership, purchased locks, competition history) establishes legitimate intent.

**International:**

| Country / Region | Status |
|-----------------|--------|
| UK | Legal; possession alone not an offense |
| Canada | Legal to own; unlawful to possess for criminal purpose |
| Germany | Legal to own |
| Japan | Restricted; lock picks are controlled tools requiring professional justification |
| Australia | Varies by state; some states require locksmith license |
| Netherlands | Legal to own |

**The rule that applies everywhere:** Only pick locks you own or have explicit permission to pick. The "in your possession" test is the universal ethical standard regardless of local law.

---

#### The Locksport Community

**Online:**

| Community | Platform | Focus |
|-----------|----------|-------|
| /r/lockpicking | Reddit | Largest English-language community; belt ranking system; feedback and progression |
| Keypicking.com | Forum | Long-running technical forum; European-heavy |
| The Open Organisation Of Lockpickers (TOOOL) | Global chapters + Discord | Competitive and educational; chapters worldwide |
| Locksport International (LSI) | locksport.com | Competitive focus; hosts championships |
| BosnianBill, LockPickingLawyer | YouTube | High-quality video reviews and picking demonstrations |

**In-person:**

- **DEF CON Lockpicking Village** - Annual; Las Vegas; competitions and open picking tables
- **TOOOL chapters** - Regular meetups in major cities worldwide
- **SSdev (Safe & Vault Technicians Association)** - Professional context; manipulation competitions
- **Locksport Europe** - Continental European championships
- **ALOA (Associated Locksmiths of America)** - Professional association; competitions at annual convention

**Etiquette at meetups:**
- Bring your own locks to trade or share
- Don't pick locks brought by others without asking
- Share techniques freely - locksport culture strongly favors open knowledge
- Beginners are welcomed; the community is notably inclusive

---

## Part II: Hands-On Techniques

### Chapter 4: Pin Tumbler Picking

#### The Physics of Single Pin Picking (SPP)

SPP exploits a universal manufacturing reality: due to tolerances, pin chambers in a lock plug are never all perfectly aligned with their driver pins simultaneously. When the plug is under light rotational tension, only **one** chamber is binding at any given moment - the rest are loose.

```
Plug under tension (exaggerated):

Chamber 1: binding  ← driver pin catches on shear line edge
Chamber 2: loose    ← driver pin floats freely
Chamber 3: loose
Chamber 4: binding  (secondary bind - will bind after 1 is set)
Chamber 5: loose
```

**Setting a pin:**
1. Apply light rotational tension to the plug with a tension wrench
2. Identify the binding pin - it feels stiffer, with less up-down play than loose pins
3. Lift the binding pin until you feel a slight plug rotation and a subtle click or give - the driver pin has set above the shear line, held by the ledge created by plug rotation
4. The next pin is now binding; repeat
5. When all pins are set, the plug rotates fully

**The key variables:**

| Variable | Effect |
|----------|--------|
| **Tension** (too much) | Pins bind so hard they're immovable; may overset |
| **Tension** (too little) | Set pins drop; no ledge formed |
| **Tension** (correct) | One pin binds at a time; set pins stay set |
| **Lifting speed** | Too fast = overset; too slow = lose the bind |
| **Pick position** | Must engage the pin stack, not the keyway wall |

#### Feedback and Tactile Vocabulary

Experienced pickers describe picking feedback in consistent terms. Developing this vocabulary accelerates skill acquisition:

| Sensation | Meaning |
|-----------|---------|
| **Stiff, resistant upward movement** | Binding pin - this is the one to set |
| **Loose, springy movement** | Non-binding pin - skip to the next |
| **Small plug rotation + slight click or give** | Pin set - move to next binding pin |
| **False set** - plug rotates partially then stops | Security pin (spool/serrated) partially set; reduce tension slightly to finish |
| **All pins feel loose** | No tension or tension wrong direction |
| **Plug snaps back** | Overset a pin; pins dropped; start over |

**The false set** is the most important sensation for intermediate pickers to master. When a spool pin is encountered, lifting it produces a partial plug rotation - the driver pin's spool waist has caught the shear line edge. Slightly reducing tension allows the plug to rotate a tiny bit more, finishing the set. Many beginners maintain constant tension and miss this entirely.

#### Tension Wrench Selection

Tension is the most important and most commonly mismanaged variable in picking.

| Wrench Type | Position | Use Case |
|-------------|----------|---------|
| **Bottom of keyway (BOK)** | Inserted at bottom, under pins | Most common; provides fine control; doesn't interfere with pick movement |
| **Top of keyway (TOK)** | Inserted at top | Better for tight keyways; slightly less fine control; pick movement below |
| **Pry bar style** | Plugs into base of keyway | Strong leverage; suited to heavy padlocks and high-tension locks |
| **Offset / low-profile** | Angled to clear the keyway | When standard wrench blocks pick travel |

Start with bottom-of-keyway on a standard keyway. Use the lightest tension that still produces a bind - most beginners use 5–10× too much tension.

#### Raking

Raking sacrifices precision for speed. A rake is moved rapidly in and out of the lock while oscillating, randomly setting and resetting pins until they all happen to align simultaneously.

Effective on cheap, low-tolerance locks. Ineffective on security pins or tight keyways.

**Common rake profiles:**

| Rake | Shape | Best For |
|------|-------|---------|
| **Bogota** | Multiple humps; aggressive | Fast raking on simple locks |
| **City rake** | Single wave profile | Medium-security locks; more controlled than Bogota |
| **Snake / S-rake** | S-shaped | Good all-around rake |
| **Worm / W-rake** | Worm profile | Older, simpler locks |
| **Dimple rake** | Narrower; shorter peaks | Dimple keyways |

**Technique:** Insert fully, apply light tension, use a scrubbing motion (in-out) combined with up-down oscillation. Vary tension and speed. If no progress in 10–15 seconds, stop, release tension, and try again - attempting to force a set makes things worse.

#### Zipping

A variation: insert rake fully, then rapidly pull it out while maintaining tension and light upward pressure. All pins are lifted simultaneously and some may catch as the rake withdraws. Requires very little technique - effective surprise method on cheap locks.

---

### Chapter 5: Lever Locks

#### Lever Lock Picking

Lever locks require a different tool and different mental model than pin tumblers. You are lifting levers, not pins - and the lock's curtain (a shield over the keyhole) means you often work partially blind.

**Tools:**
- **Lever lock pick set** - long, thin picks with various hooks designed to navigate through the curtain
- **Tension tool** - often a flat metal lever applied to the bolt itself, not the plug

**Technique (standard lever lock):**

1. Insert tension tool; apply light pressure to the bolt in the retraction direction
2. Due to bolt pressure and slight lever misalignment, one lever will be binding - its post contacts its lever more firmly than the others
3. Insert lever pick through curtain; feel for the binding lever
4. Lift the binding lever until its gate aligns with the post - you'll feel the bolt move slightly
5. Move to the next binding lever; repeat
6. All levers set = bolt retracts

**Key difference from pin tumbler:** You are moving the bolt, not rotating a plug. Feedback is in the bolt's movement rather than in plug rotation.

#### 2-in-1 Lever Picks

Some lever picks combine tension and lifting into a single tool, with one arm providing tension on the bolt and another arm lifting levers. These are often called **curtain picks** and are faster once mastered - but less precise for learning because it's harder to isolate variables.

#### Warded Locks

Older and simpler than lever locks. Wards are fixed obstructions in the keyhole that the key must navigate around. The "picks" for warded locks are **skeleton keys** - keys with most of the material removed to clear all wards simultaneously.

Warded locks provide almost no security against picking; they are primarily a key-interchange barrier rather than a security mechanism.

---

### Chapter 6: Impressioning and Key Crafting

#### Impressioning

Impressioning is the process of creating a working key from a blank by making repeated physical contact between the blank and the lock's pins, reading the marks left behind, and filing the blank until it opens the lock.

**Required materials:**
- Key blank matching the target's keyway (must fit and turn minimally)
- Set of files: needle files (flat, half-round, square)
- Magnification: loupe or stereo microscope
- Grip: vise, clamp, or purpose-built impressioning handle
- Good lighting

**Process:**

1. **Blank preparation:** Polish the top (bitting) surface of the blank lightly with fine sandpaper or a burnishing tool until it is smooth and slightly shiny. The marks will be more visible on a prepared surface.

2. **Initial marking:** Insert the blank into the lock. Apply moderate turning pressure (as if turning a key) while simultaneously applying upward pressure on the bow of the blank (wiggling it while under rotation tension). This forces each pin down onto the blank's surface.

3. **Extract and examine:** Remove the blank under good magnification. Look for bright marks - small shiny scratches where the driver pin has pressed into and displaced metal on the blank's surface.

4. **File:** File a small notch at each mark location. File perpendicular to the length of the blank. Remove only a small amount of material - less than you think.

5. **Repeat:** Re-insert, re-apply pressure, extract, examine. Marks in the center of your filed notch = correct depth, keep filing. Marks at the edges of the notch = cut is in the right spot but not deep enough. No marks in a notch = you've reached or passed the correct depth.

6. **Test and iterate:** As cuts deepen, the blank will begin to turn slightly more. A partial turn = some pins correct, others not yet. Continue until full rotation.

**Impressioning time:** Skilled impressioners open average 5-pin locks in 5–20 minutes. Competition times for expert-level locks run 15–45 minutes.

**Tips:**
- Rotate tension with each mark attempt - wiggling in only one direction can produce misleading marks
- Use consistent pressure; variable pressure produces inconsistent marks
- A fresh blank shows clearer marks than a re-polished one - when confused, start fresh
- Work in natural light or strong white LED; shadow changes how marks appear

---

#### Key Crafting from a Blank

When the bitting of a key is known (from a code, a decoded depth-key reading, or a captured original key), you can cut a working key from a blank using files alone.

**Key measurement systems:**

Most locks use a documented bitting specification:
- **Depth values:** Each cut position has a numbered depth (0 = no cut, 5 or 9 = deepest cut depending on system)
- **Spacing:** Distance between cuts is standardized per keyway family
- **MACS (Maximum Adjacent Cut Specification):** Maximum allowed depth difference between adjacent cuts - exceeding MACS makes a key that physically won't insert or will break

**Manual key cutting process:**

1. Obtain the bitting code (from manufacturer lookup by key number, from a depth gauge measurement, or decoded from a photograph)
2. Source the correct blank (key blank cross-reference databases: Ilco, Silca, HPC)
3. Mark cut positions with a scribe using a spacing template or depth gauge
4. File to the specified depth at each position, checking against a depth gauge template
5. Smooth cuts; test in lock

**Depth keys:** A set of pre-cut reference keys, one for each depth value in the bitting system, used as depth templates when hand-cutting.

---

### Chapter 7: Combination Safe Manipulation

#### Manipulation vs. Other Entry Methods

Safe entry methods ranked by skill requirement and invasiveness:

| Method | Skill Required | Damage | Speed |
|--------|---------------|--------|-------|
| **Manipulation** | High | None | Hours |
| **Scoping** | Medium | Minor (drill hole) | 30–90 min |
| **Drilling** | Medium | Moderate | 15–60 min |
| **Grinding / cutting** | Low | Severe | 15–30 min |

Manipulation is the locksport-relevant method - no damage, no drilling, recoverable afterward.

#### Safe Lock Mechanics

A standard 3-wheel combination lock:

```
Dial → Spindle → Drive cam (wheel 3)
                     │ 
               [Pick-up pin/fly]
                     ↓
              Wheel 2 → Wheel 1
              
Each wheel has a notch (gate).
When all three gates align, the fence drops into them,
releasing the bolt.
```

**Manipulation exploits:** The fence is spring-loaded. When it contacts the wheel surface while you rotate the dial, you can feel (or graph) the slight resistance as it passes over each wheel's notch. By systematically measuring these contact points, you can determine each wheel's gate position.

#### The Manipulation Process

**Equipment:**
- Dial indicator / feeler gauge on the dial handle for precise rotation measurement
- Manipulation graph paper (or digital equivalent)
- Good lighting and a comfortable working position
- Patience

**Step 1: Contact Points**

Rotate the dial while holding the handle with very light upward or downward pressure (direction depends on bolt orientation). As you rotate, the fence contacts the wheel surface. Note the dial positions where you feel a slight "drop" or change in resistance - these are the **contact points** where the fence is contacting a wheel's notch.

**Step 2: Building the Graph**

Plot resistance readings against dial position on a manipulation graph. Three wheels produce three distinct contact zones. The graph will show valleys or dips at each wheel's gate position.

```
Resistance
    │
 ───┤
    │        valley         valley          valley
    │       (wheel 3)      (wheel 2)       (wheel 1)
    └────────────────────────────────────────── Dial position
        0    10   20   30   40   50   60   70   80   90
```

**Step 3: Isolating Wheels**

Each wheel contacts the fence only at specific dial positions depending on how many times you've rotated (which wheel you've engaged). Standard procedure:

- **4-2-1 dialing procedure:** Four rotations right (engage all wheels), two left (disengage wheel 3), one right (engage wheel 1 only). Vary stopping point on final rotation to map wheel 1's gate.
- Repeat with modifications to isolate wheels 2 and 3 independently

**Step 4: The Opening**

Once all three gate positions are identified, dial them in sequence using the standard combination procedure. If manipulation was successful, the lock opens.

**Realistic expectations:** Manipulation of a quality safe lock requires 2–8 hours for a skilled practitioner. Some high-security safe locks incorporate anti-manipulation features (false gates, relockers triggered by manipulation attempts) that significantly complicate the process.

---

### Chapter 8: Tools of the Trade

#### Pick Sets

**Starter set recommendation:** Don't start with a 50-piece kit. Most picks go unused. A focused starter kit:

- Short hook (SH): SPP workhorse for most pin tumblers
- Medium hook (MH): Deeper keyways, longer plugs
- Offset hook: Navigating wards
- City rake: General raking
- Bogota rake: Fast raking
- Tension wrenches: BOK and TOK, at least two widths each

**Premium manufacturers:**

| Brand | Known For | Price Range |
|-------|-----------|------------|
| **Peterson** | Gold standard; thin, strong, excellent feel | $25–$60/pick |
| **Sparrows** | Best value; solid steel; good beginner-intermediate | $15–$45/set |
| **Multipick** | European; high-quality; lever lock specialization | $30–$80/pick |
| **Southord** | Budget-friendly starter; adequate for learning | $10–$30/set |
| **Covert Instruments** | Specialty and slim tools; covert carry focus | $20–$50/pick |
| **Red Team Tools** | High-end; specialty designs | $30–$70/pick |

**Material:** High-carbon spring steel (most picks). Titanium (some premium picks - lighter, non-magnetic, corrosion-resistant). Avoid stainless steel (too brittle, snaps under lateral load).

**Handle style:** Preference varies. Solid handles (Peterson) provide better feedback transmission for SPP. Padded handles reduce hand fatigue during long sessions. Try both.

---

#### Tension Wrenches

Often more important than the pick. Invest in a range:

- **Light tension:** For security pins; most modern locks
- **Heavy tension:** Older padlocks; very corroded or worn locks
- **Narrow profile:** Tight keyways (Kwikset, paracentric)
- **Wide profile:** Standard keyways; gives more surface area

The **Sparrows Tension Packs** provide an excellent range. The **Peterson pry bar** is the standard for heavy padlocks.

---

#### Files for Impressioning and Key Cutting

| File Type | Cut | Use |
|-----------|-----|-----|
| **Flat needle file** | Fine or medium | Key cuts; general material removal |
| **Half-round needle file** | Fine | Curved cut profiles; smoothing |
| **Square needle file** | Fine | Tight corners; narrow cut profiles |
| **Pippin (oval) needle file** | Fine | Specialty profiles |
| **Swiss pattern #4 cut** | Extra fine | Final smoothing; critical dimension work |

Key cutting files should be kept separate from general workshop files. Contamination with steel filings from other work dulls teeth faster.

---

#### Magnification Tools

Impressioning and lock analysis both benefit enormously from magnification.

| Tool | Magnification | Use |
|------|--------------|-----|
| **Jeweler's loupe (10×)** | 10× | Reading impression marks; portable |
| **Stereo microscope (10–40×)** | 10–40× | Best for impressioning; hands-free; depth perception |
| **Digital microscope / USB scope** | 20–200× | Recording marks; showing others; fine detail |
| **OptiVisor / head loupe** | 2–3.5× | Hands-free; wider field of view; filing work |
| **Phone macro lens clip** | Variable | Budget option; surprisingly effective |

A stereo microscope on the bench is the single biggest upgrade for impressioning quality. The Amscope SM-1TSZ (~$200) is the budget-conscious recommendation.

---

#### Safe Manipulation Tools

| Tool | Purpose |
|------|---------|
| **Dial indicator** | Precise dial position measurement during manipulation |
| **Manipulation graph paper** | Plotting contact points; visual pattern recognition |
| **Feeler gauge set** | Measuring fence contact resistance variations |
| **Safe scope (borescope)** | Post-drill visual inspection; not for manipulation |
| **Stethoscope (amplified)** | Acoustic detection of internal contact points |

---

#### Depth Measurement Instruments

**Depth gauge / caliper combination:** A digital caliper modified or used with a key depth gauge insert allows precise measurement of existing key bitting depths, enabling key duplication by measurement.

**Key decoder:** A tool (sometimes a pick-like instrument) that, when inserted into the lock's keyway, contacts each pin stack and reads the bitting depth directly. Useful for key duplication without the original key present (authorized use only).

**HPC Codebreaker / Lishi tools:** Commercial key-reading tools that decode the bitting of a lock in-situ. The Lishi 2-in-1 tool is particularly notable - combines a pick and decoder in one instrument, allowing picking and simultaneous bitting readout.

---

### Chapter 9: Advanced Lock Types

#### Security Pins

Security pins are the most important intermediate concept in locksport. Most locks rated "moderate" or above use them.

**Spool Pins (most common):**

```
Cross-section of spool pin:
     ___
    |   |   ← top (wide)
    |   |
     | |    ← waist (narrow)
    |   |
    |___|   ← bottom (wide)
```

When the waist catches on the shear line during picking, the plug rotates partially - this is the **false set**. The picker feels a small rotation and may mistakenly think the lock is about to open. To resolve: reduce tension slightly while maintaining upward pressure on the spool pin. The reduced tension allows the plug to rotate slightly more, pulling the spool pin's top edge past the shear line into a true set position.

**Serrated Pins:**

Multiple grooves cut into the driver pin. Each groove creates a potential false set position. The picker must recognize and work through multiple false sets per pin. Resolving serrated pins requires the same tension-reduction technique as spools but may need to be applied 2–4 times per pin.

**Combination stacks (spool + serrated):** Some high-security locks use both types in the same lock - some chambers with spools, some with serrated pins. The picker must identify which type each pin is and apply the correct technique.

---

#### Wards and Keyways

Wards are fixed obstructions in the keyhole that restrict what can enter and where. They serve two purposes: key control (preventing wrong keys from entering) and pick resistance (limiting pick maneuverability).

**Keyway complexity spectrum:**

| Keyway Type | Complexity | Pick Challenge |
|-------------|-----------|---------------|
| Simple/open (Master Lock no-name) | Low | Any pick fits easily |
| Standard residential (Kwikset) | Medium | Standard picks work; minor navigation |
| Paracentric (Medeco, ASSA) | High | Only thin picks fit; limited angles |
| Security keyway (Abloy) | Very high | Highly restricted access; specialized tools |

**Paracentric keyways** are intentionally convoluted - bowed, curved walls that require picks to navigate around wards while maintaining the correct approach angle to the pins. The Medeco keyway is a classic example: requires a very thin pick inserted at an angle, with limited lateral movement range.

---

#### Dimple Locks

In a dimple lock, the key bitting is on the flat faces of the key rather than the edge. Dimples (circular indentations) at precise locations on the key surface lift pins that are arranged radially around the plug rather than in a single row.

- Often bidirectional (key inserts either way)
- Higher pin counts common (6–8 pins per side)
- Require narrower, specialized picks (dimple picks)
- Common brands: ABUS Plus, Kaba, some Mul-T-Lock variants

**Picking dimple locks:** Same SPP principles apply, but the pick must reach pins on multiple planes. Dimple picks have a specifically shaped tip designed to engage the circular pin bottoms without slipping off.

---

#### Antique Locks

Antique locks present unique challenges and rewards for locksport practitioners:

| Lock Type | Era | Mechanism | Picking Approach |
|-----------|-----|-----------|-----------------|
| Warded padlock | Pre-1900 | Simple wards | Skeleton key; easy |
| Victorian lever deadbolt | 1850–1920 | 2–4 lever system | Lever techniques; often corroded |
| Scandinavian padlock | 1900–1950 | 2–4 levers | Lever pick; old curtain designs |
| Early pin tumbler | 1900–1940 | 4–5 pins, loose tolerances | Easy to pick; very forgiving |
| Brass chest lock | Varies | Warded or simple lever | Often unique; improvised tools sometimes needed |

**Antique lock considerations:**
- **Corrosion:** Internal parts may be frozen with rust or verdigris. Penetrating oil (Kroil, not WD-40) soaked for hours or days before attempting manipulation
- **Fragility:** Old springs break easily. Apply very light tension. If anything feels like it's going to snap, stop.
- **Value:** Collectible antique locks can be devalued by damage. When in doubt, don't force it.
- **Lubrication post-pick:** After manipulation, apply museum-quality oil (Renaissance Wax for external surfaces; light machine oil internally) to prevent future corrosion

---

## Part III: Competition Insights

### Chapter 10: Competition Setup and Hosting

#### Types of Locksport Competitions

| Format | Description | Time Pressure |
|--------|-------------|--------------|
| **Speed picking** | Open a series of locks as fast as possible | High |
| **Head-to-head** | Two pickers, same locks, first to finish wins | Extreme |
| **PicTacToe™** | Tic-tac-toe board of locks; strategy plus speed | High |
| **Escape challenge** | Pick locks to escape a scenario/room | Moderate |
| **Impressioning** | Impression a lock from a blank; scored on time | Moderate |
| **Safe manipulation** | Manipulate a combination lock; often timed | Low (hours permitted) |
| **Lock design challenge** | Design/build a pickable lock | None (judged) |

---

#### Competition Lock Tables

A standard competition table setup:

```
Competitor station:
┌─────────────────────────────────────────────────────┐
│  Lock 1    Lock 2    Lock 3    Lock 4    Lock 5      │
│  [easy]   [medium]  [medium]  [hard]    [hard]       │
│                                                      │
│  [Tension wrench holder]  [Pick roll/stand]          │
│  [Timer display]          [Attempt log sheet]        │
└─────────────────────────────────────────────────────┘
```

**Lock selection for competitions:**
- Grade locks by difficulty bracket; clearly mark or disclose difficulty tiers
- All competitors use identical lock sets (same lot where possible - bitting and tolerances vary)
- Locks should be tested and confirmed to open smoothly before competition
- Provide fallback locks (spares) in case a lock is damaged during competition

---

#### Tool Rules

Most competitions use a standard tool policy:

- **Allowed:** Any pick, tension wrench, or manipulation tool that fits the keyway without modification to the lock
- **Prohibited:** Destructive tools (drills, grinders), key blanks (unless impressioning event), lock picks with recording devices
- **Brought tools:** Competitors typically bring their own picks; some events have loaner sets for beginners
- **Inspection:** Higher-level competitions may inspect tools for prohibited modifications

---

#### Hosting Your Own Competition

**Pre-event checklist:**

- [ ] Acquire and test competition locks (all confirmed to open; spares prepared)
- [ ] Build or source lock stands / boards
- [ ] Establish and publish rules clearly (allowed tools, scoring method, tie-break procedure)
- [ ] Set up timing system (stopwatch, or dedicated scoring app)
- [ ] Arrange judging (one judge per competitor for head-to-head; roving judges for open format)
- [ ] Prepare score sheets or digital scoring
- [ ] Establish categories (beginner / intermediate / advanced) based on belt ranking or self-declaration
- [ ] Brief all judges on dispute resolution process

**Scoring systems:**

| Format | Scoring Method |
|--------|---------------|
| Speed | Elapsed time; fastest wins |
| Points | Each lock has a point value; most points in time limit wins |
| PicTacToe | Standard tic-tac-toe scoring; lines wins |
| Impressioning | Time to open; penalty for excess blanks used |
| Multi-lock | Number of locks opened in fixed time |

---

### Chapter 11: Strategy, Nerves, and Lock Intel

#### Pre-Competition Lock Intel

Gathering information about competition locks before the event is a legitimate part of competitive locksport. This is not cheating - knowing a lock's characteristics is part of the skill.

**Research sources:**
- **LockWiki / /r/lockpicking Wiki:** Profiles of common competition locks; known pin configurations; picking difficulty notes
- **YouTube (LockPickingLawyer, BosnianBill):** Video reviews often show internal configuration, false sets expected, picking approach
- **Community forums:** Past competitor threads from same event or same lock model
- **Manufacturer specifications:** Security pin types, key blank family, known keyway restrictions

**Lock profiling template:**

```
Lock: [Manufacturer Model]
Pin count: [N]
Security pins: [Spool / Serrated / Mixed / None]
Keyway: [Name / complexity level]
Known picking approach: [SPP / Rake / Combination]
False set behavior: [Describe]
Tension recommendation: [Light / Medium / Heavy; BOK/TOK]
Typical open time (skilled picker): [Range]
Known weaknesses: [If any]
Notes: [Additional observations]
```

Build and maintain a personal lock database. Competition locks repeat across events.

---

#### Competition Strategy

**Lock ordering:**
- In points-based competitions, open the highest-value locks you can open quickly - don't spend 20 minutes on a hard lock when three medium locks would score more points
- Know your own speed profile; don't attempt locks above your reliable tier in early rounds

**The reset problem:**
- Locks in competition are often picked and reset many times; worn set pins, slightly deformed shear line, and residual pin position from previous picker all affect behavior
- When a lock "doesn't feel right," release tension completely, reinsert tool, and start fresh - you may be fighting the previous picker's overset pins

**Time management:**
- Set a personal time limit per lock (e.g., 3 minutes); if not making progress, move on
- Return to difficult locks if time permits after easier locks are cleared

---

#### Managing Nerves

Competition anxiety is real and affects even experienced pickers. Physiological effects (elevated heart rate, hand tremor, sweaty hands) directly impair picking performance.

**Pre-competition:**
- Practice under simulated pressure: set a timer; have someone watch you; pick in front of others at meetups
- Build familiarity with competition format by spectating or volunteering at events before competing
- Physical preparation: sleep, light food, avoid excess caffeine day-of

**During competition:**

| Problem | Response |
|---------|----------|
| Hand tremor | Pause; slow breathing for 30 seconds; lighter grip on tools |
| Losing tension control | Switch to heavier tension wrench; more surface contact helps proprioception |
| Mental blank ("all pins feel the same") | Release completely; reinsert; deliberately find the binding pin before lifting anything |
| Over-analyzing | Trust muscle memory; return to basics |
| Dropped tool | Breathe; retrieve calmly; restart methodically |

**The reset ritual:** Many competitive pickers develop a physical reset routine - a specific series of movements (set down pick, take two slow breaths, re-grip) used when things go wrong. The ritual interrupts the anxiety loop and cues the practiced, calm picking state.

---

#### Physical Setup for Competition

Often overlooked factors that affect performance:

- **Seating and posture:** Picking works best when your arms are supported and relaxed. A chair at bench height beats standing over a table.
- **Lock orientation:** Can you rotate the lock for better pick approach angle? Confirm with judges what's allowed.
- **Lighting:** Bring your own small LED light. Competition lighting is often uneven.
- **Tool organization:** Have your tools laid out in a consistent arrangement so you're not searching during competition.
- **Hand warmth:** Cold hands significantly reduce tactile sensitivity. Keep hands warm before competing.

---

### Chapter 12: Competition Formats

#### Head-to-Head Speed Picking

Two competitors sit at adjacent identical lock sets. On the signal, both begin. First to open all locks (or a specified lock) wins the round. Tournament bracket proceeds until a champion is determined.

**Judging:**
- Judge confirms the lock is fully open (plug fully rotated or shackle fully released)
- In case of dispute about simultaneous completion, judge's call is final
- Damaged lock = competitor continues with a replacement (time penalty or judge discretion per rules)

**Psychology of head-to-head:** Hearing your opponent open a lock is a significant psychological event. The best competitors report hearing this and using it as motivation rather than distraction - acknowledging it consciously and refocusing on their own lock.

---

#### PicTacToe™

A format developed in the locksport community that adds strategic decision-making to lock picking.

**Setup:**
- Nine locks arranged in a 3×3 grid; each lock occupies a tic-tac-toe square
- Locks vary in difficulty by position (corners = hardest, center = medium, edges = easiest - or variations thereof)
- Two competitors; competitor A picks an open lock to "claim" a square; competitor B does the same; standard tic-tac-toe victory conditions

**Strategy layer:**
- Claiming easy locks quickly can establish a line; opponent must block, forcing them onto harder locks
- Forcing the opponent into a corner lock (hardest) while you take center is a strong opening
- Experienced pickers will have profiled all nine locks; less experienced pickers may not know which squares are difficult until they attempt them

**Skill + strategy balance:** PicTacToe rewards competitors who are both fast on easy locks and can reliably open harder locks - pure speed on easy locks without ability to finish medium locks loses to a strategic player.

---

#### Escape Challenges

Locks are integrated into a scenario - you must pick them in sequence or in combination to "escape" the challenge. Common at conventions and DEF CON Lockpicking Village.

**Format variations:**
- Chained locks: Lock A opens a box containing key to lock B; etc.
- Timed room: Multiple locks in a room-escape format; find and pick to exit
- Puzzle integration: Lock picking combined with other puzzle elements

**Preparation:**
- Escape challenges often use obscure or unusual locks specifically to challenge experienced pickers - research what previous iterations of the same event used
- Multi-step scenarios require lock recognition (identifying lock type and approach quickly) more than pure picking speed

---

#### Impressioning Competitions

Competitors are given identical locked padlocks and a set of blanks (usually 3–5). Scored on time to open. Penalty time added per additional blank used.

**Competition-specific technique adjustments:**
- Under competition pressure, the tendency is to over-file - take smaller passes and check more frequently than in practice
- The penalty for extra blanks incentivizes working carefully on one blank rather than discarding and starting over
- Practiced impression readers can see marks after 2–3 attempts; beginners often need many more

---

#### Safe Manipulation Competitions

Common at SSV (safe and vault) trade events and some locksport championships.

- Identical safe locks pre-set to unknown combinations
- Competitors attempt to manipulate open; scored on time
- Expert competitors may open a standard 3-wheel lock in 1–2 hours; beginners may not open within the time limit
- Often allows scoping (post-drill borescope inspection) as an alternative for competitors who can't complete manipulation - scored separately

---

## Further Reading and Resources

**Books:**
- *Keys to the Kingdom* - Deviant Ollam (lockpicking for physical penetration testing)
- *Practical Lock Picking* - Deviant Ollam (technique reference; widely used)
- *Open Organization Of Lockpickers (TOOOL) Handouts* - Free PDF; excellent technical foundation

**Online Learning:**
- /r/lockpicking wiki and the **Belt Ranking** progression guide
- LockPickingLawyer (YouTube) - 1,700+ lock reviews and picks; invaluable reference library
- BosnianBill (YouTube) - Deep technical dives; security pin analysis; tool reviews
- Keypicking.com - Technical forum; European locks; experienced community

**Competitions:**
- **DEF CON Lockpicking Village** - defcon.org; annual; Las Vegas
- **TOOOL events** - toool.us; chapter events worldwide
- **Locksport International** - locksport.com (the `locksportinternational.com` domain no longer resolves; `locksport.com` is the org's current domain per Wikipedia, though the site itself returns intermittent server errors as of this writing)
- **ALOA Annual Convention** - aloa.org; professional context; manipulation competitions

**Sourcing Locks and Supplies:**
- eBay / Craigslist - Bulk lots of used padlocks; economical practice supply
- Lock pick supply vendors: Peterson (lockpickshop.com), Sparrows, Southord
- Pinning kits and blanks: Multiplex, Hudson, Arrow (locksmith supply distributors)
- Impressioning blanks: Ilco, Silca blank catalogs; key blank cross-reference at iLco.com

---

## Related Files
- [README.md](README.md) - Documentation section index: all guides and cheat sheets in this directory
- [flipper_zero_guide.md](flipper_zero_guide.md) - Flipper Zero physical access features (RFID/NFC cloning, iButton) complement physical lock bypass skills
- [bruce_firmware.md](bruce_firmware.md) - Bruce firmware includes 125 kHz RFID and 13.56 MHz NFC cloning (electronic complement to physical locksport)
- [evil_m5.md](evil_m5.md) - Evil-M5 NFC/RFID features for badge cloning alongside physical access assessment
- [../HardwareHacking/Chapter1.md](../HardwareHacking/Chapter1.md) - Hardware hacking fundamentals: physical layer access complements lock bypass in red-team engagements

---

*Document maintained as part of the ULTIMATE-CYBERSECURITY-MASTER-GUIDE. For corrections or contributions, submit a PR to the repository.*

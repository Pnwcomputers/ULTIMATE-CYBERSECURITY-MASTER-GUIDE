# 🖨️ Design for 3D Printing: Tolerances, Orientation & Snap Fits

_Last reviewed: 2026-11-14_

*Part of the [OpenSCAD Design & Prototyping Guide](./README.md) · [CAD & 3D Printing](../README.md) · [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md)*

**Navigate:** [OpenSCAD Hub](./README.md) · [Fundamentals](./01-fundamentals.md) · [Project Structure](./02-project-structure.md) · [Mockups & Fit Checks](./03-mockups-and-fit-checks.md) · [GPS Cradle Tutorial](./04-tutorial-gps-cradle.md) · **Design for Printing** · [Shortcuts](./06-keyboard-shortcuts.md)

## 🎯 Purpose

Turning a model that *fits on screen* into a part that *fits in your hand*. This page covers fused-filament (**FDM**) printing realities: clearances, hole sizing, wall and layer math, orientation and strength, overhangs, snap-fit design, multi-color inlays, export formats and troubleshooting.

> [!NOTE]
> Numbers on this page are **starting points** for a typical 0.4 mm nozzle and 0.2 mm layers. Printers, materials and slicer settings differ. The only reliable tolerance is the one you measured from a test coupon on your own machine.

---

## Contents

1. [Tolerances & Fits](#tolerances--fits)
2. [Walls, Lines & Layers](#walls-lines--layers)
3. [Holes & Bosses](#holes--bosses)
4. [Orientation & Strength](#orientation--strength)
5. [Overhangs, Bridges & Supports](#overhangs-bridges--supports)
6. [Snap Fits](#snap-fits)
7. [Multi-Color Inlays](#multi-color-inlays)
8. [Materials for Field Gear](#materials-for-field-gear)
9. [Exporting](#exporting)
10. [Troubleshooting](#troubleshooting)

---

## Tolerances & Fits

Always state clearances **per side** in code (`fit_gap`), and convert to diameter only where a formula needs it.

| Fit | Clearance Per Side (Start Here) | Used For |
|---|---|---|
| Press / interference | 0 to −0.05 mm | Magnets, bearings, pins you never remove |
| Snug slide | 0.15–0.20 mm | Lids that should not rattle |
| Free slide | 0.25–0.35 mm | Device sleeves, drawers, telescoping parts |
| Loose / dirty field use | 0.4–0.5 mm | Gear that will collect grit or be used with gloves |

The tutorial uses `fit_gap = 0.30` for the handset sleeve, `snap_gap = 0.25` between a lid tab and its wall, and `pcb_gap = 0.30` around the board edge.

> [!TIP]
> Make every clearance a parameter, print a **gauge slice** that contains the fit (see [Test Coupons](./03-mockups-and-fit-checks.md#test-coupons-gauges)), and write the result back with a comment such as `// +0.05 after X1C PETG gauge`.

---

## Walls, Lines & Layers

Design dimensions that slice cleanly:

| Feature | Rule | Example |
|---|---|---|
| Wall thickness | Whole multiples of line width (≈ nozzle × 1.1) | `wall = 1.8` = 4 × 0.45 mm |
| Thin features | At least 2 lines | `trace_w = 0.9` = 2 × 0.45 mm |
| Thin plates / inlays | Whole multiples of layer height | `lid_t = 1.6` = 8 × 0.2 mm, `trace_d = 0.4` = 2 layers |
| Minimum printable wall | About 2 lines; below that, gaps or missing walls | Avoid walls under 0.8 mm |

Check a slice in the slicer's preview: if a wall shows a gap fill or a missing line, nudge the parameter to the next multiple.

---

## Holes & Bosses

- **Holes print small.** Polygon flats sit inside the true circle and the first layers squish inward. Add clearance (0.2–0.4 mm on diameter for small holes) and verify with a **hole ladder** like the tutorial's `sma_gauge`.
- **Horizontal holes droop.** The top of a hole printed sideways is an unsupported arc. Fix it with a **teardrop** (a 45° point on top) or a **flat top** (like the SMA hole's D-flat facing up).
- **Threaded inserts and screws:** use the insert or screw vendor's recommended hole size, then confirm with a test boss. Give bosses at least 2–3 walls around the hole.
- **Nut traps:** a 6-sided cylinder, `d = across_flats / cos(30)`, plus 0.2–0.3 mm.

```openscad
// Teardrop hole along X: round bottom, 45-degree point on top (+Z)
module teardrop_x(d, len) {
    rotate([0, 90, 0]) linear_extrude(height = len, center = true)
        hull() {
            circle(d = d);
            translate([-d / 2 / sqrt(2), 0]) rotate(45) square(d / 2, center = true);
        }
}
```

---

## Orientation & Strength

FDM parts are **anisotropic**: strong along the extruded lines, weakest **between layers**. Choose orientation per part:

1. **Find the load.** Which feature bends or takes impact (snap arms, clips, thin lips)?
2. **Lay that feature in the XY plane** so its bending stress runs along the lines.
3. **Then** minimize supports and pick the best-looking face for the bed.

How the tutorial applies this:

| Part | Print Pose | Reason |
|---|---|---|
| Body | Standing on the sleeve's open end (`stand()`) | Arms, lip, plate and pod walls are vertical; PCB latch arms lie within layers (strong); SMA flat faces up |
| Lid | Flat, outside face down | Smooth outer face, inlay in the first two layers; tabs are vertical, so engagement is kept small |
| Gauges | Flat | Fast, and the fit surfaces are crisp |

> [!WARNING]
> A clip that bends across layer lines will usually snap along a layer the first time it flexes. If a feature *must* bend across layers, keep its strain low, add a root fillet, raise the wall-line count and use a tougher material.

---

## Overhangs, Bridges & Supports

| Situation | Rule of Thumb | Design Fix |
|---|---|---|
| Overhang angle | Up to about 45° from vertical prints without support | Chamfer undersides at 45° instead of flat ledges |
| Bridges | Short straight spans (a few mm to ~20 mm) print well | Rectangular windows bridge better than round ones; keep spans short |
| Horizontal holes | Top arc droops | Teardrop or flat-top holes |
| Arches at the top of a standing part | Usually fine at enclosure sizes | Enable supports for the outer arch only if it sags |
| First-layer "elephant's foot" | Bottom edge bulges | 0.4–0.6 mm chamfer on bed-side edges (the lid's `lid_chamfer`) |

---

## Snap Fits

A cantilever snap is a small beam that bends while you push the parts together and springs back into a recess. Design it by **strain**, not by guesswork.

For a constant rectangular section with the deflection at the tip (the classic cantilever equation from the Bayer and BASF snap-fit design guides):

```text
strain = 1.5 × t × y / L²
  t = arm thickness in the bending direction
  y = deflection needed to clear the hook (the undercut)
  L = arm length from root to hook
```

```openscad
function snap_strain(t, y, L) = 1.5 * t * y / (L * L);
echo(snap_strain(1.2, 0.6, 7));   // 0.022 -> 2.2 %
```

| Lever | Effect on Strain | Notes |
|---|---|---|
| Longer arm (`L`) | Falls with the **square** of length | The most effective fix |
| Thinner arm (`t`) | Falls linearly | Also lowers holding force |
| Smaller hook (`y`) | Falls linearly | Less retention |
| Taper the arm toward the tip | Spreads strain evenly | Bayer guide's preferred shape |
| Root fillet | Lowers stress concentration | Add when the arm cracks at its base |

**Design limits:** stay well below the filament's **elongation at yield** from its technical data sheet. Published values for printed test bars are roughly **2–3 %** for PLA (for example Prusament PLA 2.9 %, Ultimaker PLA 3.3 %) and roughly **3–6 %** for PETG (for example Prusament PETG 5.1 %, Push Plastic PETG 3.25 %). Practical starting points for snaps you open repeatedly: about **1.5–2 %** for PLA and **about 3 %** for PETG, ASA or ABS. Printed parts are weaker between layers than these bars, so test a coupon.

The tutorial asserts both snaps stay under `max_strain` and echoes the values (2.2 % lid tab, 2.3 % PCB latch): comfortable in PETG, near the limit in PLA.

Other snap-fit details used in the tutorial:

- **Lead-in ramp** on the free end so the arm deflects smoothly.
- **Catch face slope** (`catch_dz`): 0 is permanent, a small slope makes it releasable.
- **Play** under the hook (`pcb_play = 0.2`) so it does not clamp or bow the board.
- **Paired cutter module** (`tab_recess()` for `cantilever_tab()`), placed by the same transform, so tab and recess never disagree.

---

## Multi-Color Inlays

The tutorial lid has a 0.4 mm recess and a matching `inlay` part, both exported in the **same coordinate frame**:

1. Export `lid` and `inlay` as separate STLs (`./check.sh` does this).
2. In Bambu Studio (OrcaSlicer and PrusaSlicer work the same way), select **both files in one import**. When asked *"Load these files as a single object with multiple parts?"*, choose **Yes**. The parts keep their relative positions.
3. Assign a second filament to the inlay part.
4. Print outside face down; the inlay occupies the first two layers.

> [!TIP]
> Keep inlay features at least two lines wide and two layers deep. Thinner features turn into gaps or blobs.

---

## Materials for Field Gear

| Material | Strengths | Watch Out For | Good For |
|---|---|---|---|
| PLA / PLA+ | Easy, accurate, stiff | Brittle snaps; softens in a hot car | Prototypes, gauges, desk fixtures |
| PETG | Tough, flexible snaps, decent heat | Stringing; slightly less accurate | Cradles, lids, clips, most field gear |
| ASA / ABS | Heat and UV resistant | Warping; needs an enclosure and ventilation | Vehicle-mounted or outdoor gear |
| TPU | Flexible, grippy | Hard to print accurately; poor for precise fits | Bumpers, gaskets, cable boots |
| Nylon / CF-filled | Strong, wear resistant | Moisture; abrasive (hardened nozzle); carbon fill can affect RF | Hinges, high-load brackets |

> [!WARNING]
> Keep **carbon-fiber and metal-filled** filaments away from antennas and RF paths. They can be conductive or lossy. Use plain polymers near SMA bulkheads, GPS patches and Sub-GHz antennas.

---

## Exporting

| Format | When | OpenSCAD 2021.01 |
|---|---|---|
| STL | Universal; one mesh per file | ✅ (`--export-format asciistl` or `binstl`) |
| 3MF | Modern slicers; units stored in the file | ✅ in builds with 3MF support (check with a test export) |
| AMF / OFF | Rarely needed | ✅ |
| DXF / SVG | 2D profiles for laser cutting or drawings | ✅ (2D designs or `projection()`) |
| PNG | Documentation renders | ✅ (`--imgsize`, `--camera`) |

Before exporting:

- [ ] Render (F6) shows no "may not be a valid 2-manifold" warning on printable parts
- [ ] The `part` branch applies the print orientation; the mockups are not included
- [ ] The design checks and clash test pass (`./check.sh`)
- [ ] File names include the part and, ideally, the parameter preset (`gps_cradle_body_loose-fit.stl`)

---

## Troubleshooting

| Problem | Likely Cause | Fix |
|---|---|---|
| Device will not slide in | `fit_gap` too small, elephant's foot, measured too small | Print the gauge; add 0.05–0.1 mm; chamfer bed edges |
| Device rattles | `fit_gap` too large | Reduce `fit_gap`; add a small lip or crush ribs |
| SMA thread will not pass | Hole prints undersize | Pick a larger size from `sma_gauge` |
| Snap cracks at the root | Strain too high or bending across layers | Lengthen the arm, add a root fillet, change orientation or material |
| Snap will not hold | Engagement too small or recess too loose | Increase `snap_engage` slightly; tighten the recess `clear` |
| Lid tabs miss recesses | Tab and recess placed differently | Place both with one shared transform (`at_tabs()`) |
| Window edge sags | Long top bridge | Reduce the span, round the corners, or reorient |
| Thin skins inside the STL | Coincident faces | Overshoot cutters by `eps`; avoid zero-thickness unions |
| Slicer reports open edges | Non-manifold geometry, often touching solids | Overlap by `eps` or separate; re-render with a newer build / Manifold |

---

## See Also

- Filament data sheets used for the strain figures: [Prusament PLA](https://www.matterhackers.com/r/xFvGl8), [Prusament PETG](https://www.3dprintergear.com.au/assets/files/technical-data-sheet%20(1).pdf), [Push Plastic PETG](https://cdn.shopify.com/s/files/1/0260/7421/files/Push_Plastic_PETG_Technical_Data_sheet.pdf)

- [Mockups & Fit Checks](./03-mockups-and-fit-checks.md)
- [GPS Cradle Tutorial](./04-tutorial-gps-cradle.md)
- [Bayer "Snap-Fit Joints for Plastics" design guide (mirror)](https://fab.cba.mit.edu/classes/S62.12/people/vernelle.noel/Plastic_Snap_fit_design.pdf)
- [Fictiv: How to design snap-fit components](https://www.fictiv.com/articles/how-to-design-snap-fit-components)
- [Bambu Lab wiki: split to objects / parts](https://wiki.bambulab.com/en/software/bambu-studio/split-to-objects-parts)

---
[⬅️ Back to Master Index](../../README.md) | [🎯 Role Navigation](../../START_HERE.md) | [Legal Notice](../../LEGAL.md)

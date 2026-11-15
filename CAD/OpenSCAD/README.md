# OpenSCAD Functional Design & Prototyping Guide

Welcome to the comprehensive guide for designing functional 3D-printable parts, mechanical assemblies, and hardware enclosures in OpenSCAD. This guide covers core syntax, configuration patterns, project organization, and a complete walkthrough for mocking up and building complex assemblies (such as custom device cradles, GPS modules, SMA antenna mounts, and snap-fit lids).

---

## 1. Core Syntax & Primitives
OpenSCAD is code-first CAD. Every 3D model is built using geometric primitives manipulated through mathematical transformations and boolean logic.

* **Primitives:** 
  * `cube([x, y, z], center=true/false);`
  * `cylinder(h=height, r=radius, center=true);` (or `d=diameter`)
  * `sphere(r=radius);`
  * `polyhedron(points=[...], faces=[...]);`
* **Resolution Control:** Always control curve smoothness using fragment variables:
  ```openscad
  $fn = 64; // Sets fixed number of fragments per circle (higher = smoother, lower = faster render)
  ```

---

## 2. Transformations & Boolean Operations
Position and combine shapes using transformation wrappers and CSG (Constructive Solid Geometry) operators.

### Transformations
```openscad
translate([x, y, z]) { ... } // Move in 3D space
rotate([x, y, z]) { ... }    // Rotate in degrees around X, Y, Z axes
scale([x, y, z]) { ... }     // Scale dimensions non-uniformly
mirror([x, y, z]) { ... }    // Mirror geometry across a plane
```

### Boolean Operations
```openscad
union() { ... }         // Combines multiple shapes (default behavior for multiple items)
difference() {          // Subtracts all subsequent children from the first child
    base_shape();
    cutting_tool();
}
intersection() {        // Keeps only the overlapping volume of all children
    shape_a();
    shape_b();
}
```

---

## 3. Managing Configurations & Variables in Larger Projects
As OpenSCAD projects grow, separating configuration parameters into a dedicated file (`config.scad`) keeps your codebase maintainable.

### Recommended Project Structure
```text
my_project/
├── config.scad         // All global variables, tolerances, and dimensions
├── main.scad           // Assembly file that renders the final model
└── modules/
    ├── chassis.scad    // Individual component modules
    └── lid.scad
```

### `config.scad` Example
```openscad
// ==========================================
// PROJECT CONFIGURATION & CONSTANTS
// ==========================================

/* [Global Render Settings] */
$fn = 100;

/* [Manufacturing Tolerances] */
PRINT_TOLERANCE = 0.25; // Gap for sliding or mating parts

/* [Enclosure Core Dimensions] */
BOX_WIDTH  = 120;
BOX_LENGTH = 80;
BOX_HEIGHT = 45;
WALL_THICK = 1.8;
```

---

## 4. Prototyping Workflow: Mocking Up Hardware for Fit & Clearance
When designing enclosures or brackets that interface with real-world electronics (PCBs, GPS modules, connectors), follow these prototyping strategies:

1. **Simplified Bounding Envelopes:** Build digital proxy models of your target hardware using primitive cubes and cylinders to verify alignment and prevent collisions.
2. **OpenSCAD Modifiers for Inspection:**
   * `%` (Ghost / Background): Renders geometry in transparent gray to display target devices inside your enclosure.
   * `#` (Debug / Transparent Red): Highlights cutting tools and intersecting geometry.
   * `*` (Disable): Hides mockups during final mesh exports.

---

## 5. Complete Tutorial: Designing a GPS Cradle with SMA Ports & Snap-Fit Lids

Below is a complete, production-grade OpenSCAD script demonstrating how to build a hardware cradle (similar to the LilyGO T-Embed / GT-U7 GPS assembly) featuring internal board ledges, cable routing slots, an SMA antenna bulkhead hole, and a snap-fit lid.

```openscad
// LILYGO T-Embed & GPS Cradle Reference Design
part = "preview"; // [body,lid,gauge,preview]
show_inlay = true;
lid_explode = 15; // Open rear pocket in assembly view

// Core Parameters
case_length = 97.5;
case_width  = 38.5;
case_depth  = 27.6;
side_gap    = 0;
sleeve_length = 58;
wall        = 1.8;
arm_wall    = 4.5;
$fn         = 100;

r = case_width / 2;
outer = r + side_gap + wall;
floor_z = -wall;
pw = 2 * (r + side_gap + arm_wall);
pl = sleeve_length;

module device_plan() {
    hull() for(y = [r, case_length - r]) translate([0, y]) circle(r = r);
}

module arm_outline() {
    scale([(r + side_gap + arm_wall) / (r + side_gap + wall), 1]) device_plan();
}

module slab(z, h) {
    translate([0, 0, z]) linear_extrude(h) children();
}

// Basic Enclosure Chassis Body
module cradle() {
    difference() {
        slab(floor_z, case_depth + wall + 2) arm_outline();
        // Hollow inner sleeve for device insertion
        translate([0, 0, 0]) 
            slab(-0.1, case_depth + 1) device_plan();
            
        // Cable routing slot
        translate([-6, 25, -2]) cube([12, 10, 8]);
    }
}

// GPS Module Mounting Ledges
module board_mount() {
    for(hand = [-1, 1]) {
        translate([hand * 10, 30, -6.4])
            cube([4, 15, 1.6]);
    }
}

// SMA Antenna Hole Penetration
module sma_cutout() {
    translate([15, 43.5, -3])
        rotate([0, 90, 0])
        cylinder(d = 6.8, h = 10, center = true);
}

// Complete Assembly Body
module body() {
    difference() {
        union() {
            cradle();
            board_mount();
        }
        sma_cutout();
    }
}

// Snap-Fit Lid
module lid() {
    difference() {
        cube([case_width + 6, sleeve_length, 1.6], center = true);
        // Add decorative trace pocket
        translate([0, 0, 0.5]) cube([case_width - 4, sleeve_length - 10, 0.4], center = true);
    }
}

// Render Logic based on 'part' selector
if (part == "body") body();
if (part == "lid") lid();
if (part == "preview") {
    color("SteelBlue") body();
    color("LightSteelBlue") translate([0, 29, -10 - lid_explode]) lid();
}
```

---

## 6. Best Practices for 3D Printing Functional Parts
1. **Tolerances:** Always add `0.2mm` to `0.3mm` diametrical clearance for sliding or mating parts to account for 3D printer extrusion variations.
2. **Orientation:** Print enclosures flat on their entry face or base bed to minimize support requirements.
3. **Exporting STLs:** Switch your `part` variable to `"body"` or `"lid"` and comment out mockups before exporting to `.stl` for your slicer.
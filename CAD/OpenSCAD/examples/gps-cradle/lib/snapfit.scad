// =============================================================================
// snapfit.scad — printable snap-fit features (cantilever tabs, PCB latches)
// Load with:  use <lib/snapfit.scad>
// Units: millimeters.
//
// Cantilever strain (constant rectangular section, deflection at the tip):
//     strain = 1.5 * t * y / L^2
//   t = arm thickness in the bending direction, y = deflection, L = arm length.
// Stay well below the filament's elongation at yield (datasheets: about 2-3 %
// for PLA, 3-6 % for PETG). Starting points for snaps opened repeatedly:
// ~1.5-2 % PLA, ~3 % PETG/ASA/ABS. snap_strain() below computes it.
// =============================================================================

function snap_strain(t, y, L) = 1.5 * t * y / (L * L);

// -----------------------------------------------------------------------------
// cantilever_tab(): a lid-to-wall snap.
// Local frame: the arm grows up +Z from z = 0, spans x in [-w/2, w/2] and
// y in [-t, 0]. The tooth sticks out toward +Y (toward the wall it locks into).
//   tooth = how far the tooth sticks out past the arm face
//   lead  = height of the angled lead-in ramp at the free end
//   land  = height of the flat part of the tooth
//   catch_dz = small slope on the catch face (0 = permanent, >0 = releasable)
// -----------------------------------------------------------------------------
module cantilever_tab(w = 5, t = 1.2, len = 7, tooth = 0.85,
                      lead = 1.2, land = 0.6, catch_dz = 0.3) {
    e = 0.01;
    z_catch = len - lead - land - catch_dz;
    rotate([90, 0, 90])
        linear_extrude(height = w, center = true)
            polygon([
                [-t, -e], [0, -e],
                [0, z_catch],                   // up the outer face
                [tooth, len - lead - land],     // catch face (holds the lid)
                [tooth, len - lead],            // flat land
                [0, len],                       // lead-in ramp
                [-t, len]
            ]);
}

// Pocket that receives cantilever_tab(). Same local frame as the tab, where
// the tab's outer face is at y = 0 and the wall face sits at y = gap.
module tab_recess(w = 5, len = 7, tooth = 0.85, gap = 0.25,
                  lead = 1.2, land = 0.6, catch_dz = 0.3, clear = 0.3) {
    z_catch = len - lead - land - catch_dz;
    translate([-w / 2 - clear, gap - 0.5, z_catch - clear])
        cube([w + 2 * clear, tooth - gap + 0.5 + 0.25,
              (len + clear) - (z_catch - clear)]);
}

// -----------------------------------------------------------------------------
// pcb_side_latch(): a ledge + spring arm that clips a PCB edge.
// It is a 2D profile extruded along Y, so it prints cleanly when the part
// stands on its end (the latch becomes a vertical wall).
//
// Local frame (before you place it):
//   u (= +X) points outward from the board edge; the board edge is at x = 0.
//   v (= -Z) points away from the mounting surface (the plate is at z = 0).
//   The board's back face rests on the standoff at depth `standoff`.
// -----------------------------------------------------------------------------
module pcb_side_latch(length = 8, t = 1.2, standoff = 4, pcb_t = 1.6,
                      gap = 0.3, hook = 0.4, play = 0.2,
                      land = 0.4, ramp = 1.2) {
    e = 0.01;
    catch_v = standoff + pcb_t + play;
    top = catch_v + land + ramp;
    rotate([90, 0, 0])
        linear_extrude(height = length, center = true)
            polygon([for (p = [
                [gap, -e], [gap + t, -e], [gap + t, top], [gap, top],
                [-hook, catch_v + land],        // lead-in ramp
                [-hook, catch_v],               // hook lip
                [gap, catch_v]                  // catch face
            ]) [p[0], -p[1]]]);
}

// Total spring-arm length of pcb_side_latch() (for strain checks).
function pcb_latch_len(standoff, pcb_t, play, land = 0.4, ramp = 1.2) =
    standoff + pcb_t + play + land + ramp;

// Ledge (standoff rail) the board rests on, same frame as pcb_side_latch().
module pcb_ledge(length = 20, width = 2, standoff = 4) {
    translate([-width, -length / 2, -standoff]) cube([width, length, standoff + 0.01]);
}

//! Layered graph layout for control-flow graphs (a small Sugiyama-style layout).
//!
//! 1. Find back edges (loops) with a depth-first search, so the rest is acyclic.
//! 2. Put each node in a layer: the longest path from the entry.
//! 3. Order nodes within layers by the average position of their neighbors.
//! 4. Place nodes horizontally under their predecessors without overlapping.
//! 5. Route edges: forward edges go down, back edges loop around the left side.
//!
//! Sizes and positions are in abstract units (the view multiplies by the zoom).

use egui::{Pos2, Rect, Vec2};

pub const H_GAP: f32 = 4.0;
pub const V_GAP: f32 = 3.0;

#[derive(Clone, Debug)]
pub struct EdgePath {
    pub from: usize,
    pub to: usize,
    pub points: Vec<Pos2>,
    pub back: bool,
}

#[derive(Clone, Debug)]
pub struct Layout {
    /// Top-left corner of each node.
    pub nodes: Vec<Rect>,
    pub edges: Vec<EdgePath>,
    pub bounds: Rect,
}

pub fn layout(sizes: &[Vec2], edges: &[(usize, usize)], root: usize) -> Layout {
    let n = sizes.len();
    if n == 0 {
        return Layout {
            nodes: Vec::new(),
            edges: Vec::new(),
            bounds: Rect::NOTHING,
        };
    }
    let mut succs = vec![Vec::new(); n];
    for &(a, b) in edges {
        succs[a].push(b);
    }

    // 1. Back edges via iterative DFS.
    let mut state = vec![0u8; n]; // 0 new, 1 on stack, 2 done
    let mut back = vec![false; edges.len()];
    let mut dfs_order = Vec::with_capacity(n);
    let mut roots: Vec<usize> = vec![root];
    roots.extend((0..n).filter(|&i| i != root));
    for r in roots {
        if state[r] != 0 {
            continue;
        }
        let mut stack = vec![(r, 0usize)];
        state[r] = 1;
        dfs_order.push(r);
        while let Some((node, i)) = stack.pop() {
            if i < succs[node].len() {
                stack.push((node, i + 1));
                let next = succs[node][i];
                match state[next] {
                    0 => {
                        state[next] = 1;
                        dfs_order.push(next);
                        stack.push((next, 0));
                    }
                    1 => {
                        for (e, &(a, b)) in edges.iter().enumerate() {
                            if a == node && b == next {
                                back[e] = true;
                            }
                        }
                    }
                    _ => {}
                }
            } else {
                state[node] = 2;
            }
        }
    }

    // 2. Longest-path layering over forward edges (Kahn's algorithm).
    let mut indegree = vec![0usize; n];
    for (e, &(_, b)) in edges.iter().enumerate() {
        if !back[e] {
            indegree[b] += 1;
        }
    }
    let mut layer = vec![0usize; n];
    let mut queue: Vec<usize> = (0..n).filter(|&i| indegree[i] == 0).collect();
    while let Some(node) = queue.pop() {
        for (e, &(a, b)) in edges.iter().enumerate() {
            if a == node && !back[e] {
                layer[b] = layer[b].max(layer[a] + 1);
                indegree[b] -= 1;
                if indegree[b] == 0 {
                    queue.push(b);
                }
            }
        }
    }
    let layers_count = layer.iter().max().map_or(1, |m| m + 1);

    // Dummy nodes: a forward edge that skips layers gets an invisible waypoint in every
    // layer it crosses, so ordering and placement route it around real blocks instead
    // of straight through them.
    let mut vsize: Vec<Vec2> = sizes.to_vec();
    let mut vlayer = layer.clone();
    let mut vpreds: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut vsuccs: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut chains: Vec<Vec<usize>> = vec![Vec::new(); edges.len()];
    for (e, &(a, b)) in edges.iter().enumerate() {
        if back[e] {
            continue;
        }
        let mut prev = a;
        for l in layer[a] + 1..layer[b] {
            let d = vsize.len();
            vsize.push(Vec2::new(1.0, 0.0));
            vlayer.push(l);
            vpreds.push(vec![prev]);
            vsuccs.push(Vec::new());
            vsuccs[prev].push(d);
            chains[e].push(d);
            prev = d;
        }
        vsuccs[prev].push(b);
        vpreds[b].push(prev);
    }
    let vn = vsize.len();
    let mut layers: Vec<Vec<usize>> = vec![Vec::new(); layers_count];
    for &node in &dfs_order {
        layers[layer[node]].push(node);
    }
    for d in n..vn {
        layers[vlayer[d]].push(d);
    }

    // 3. Barycenter ordering, a few sweeps down and up.
    let mut position = vec![0f32; vn];
    let refresh = |layers: &Vec<Vec<usize>>, position: &mut Vec<f32>| {
        for l in layers {
            for (i, &node) in l.iter().enumerate() {
                position[node] = i as f32;
            }
        }
    };
    refresh(&layers, &mut position);
    for sweep in 0..6 {
        let down = sweep % 2 == 0;
        let order: Vec<usize> = if down {
            (1..layers_count).collect()
        } else {
            (0..layers_count.saturating_sub(1)).rev().collect()
        };
        for li in order {
            let mut keyed: Vec<(f32, usize)> = layers[li]
                .iter()
                .map(|&node| {
                    let neighbors = if down { &vpreds[node] } else { &vsuccs[node] };
                    let key = if neighbors.is_empty() {
                        position[node]
                    } else {
                        neighbors.iter().map(|&m| position[m]).sum::<f32>() / neighbors.len() as f32
                    };
                    (key, node)
                })
                .collect();
            keyed.sort_by(|a, b| a.0.total_cmp(&b.0));
            layers[li] = keyed.into_iter().map(|(_, node)| node).collect();
            refresh(&layers, &mut position);
        }
    }

    // 4. Coordinates.
    let gap = |a: usize, b: usize| if a >= n || b >= n { H_GAP / 2.0 } else { H_GAP };
    let mut x = vec![0f32; vn];
    let mut layer_top = vec![0f32; layers_count];
    let mut layer_height = vec![0f32; layers_count];
    let mut top = 0f32;
    for (li, l) in layers.iter().enumerate() {
        let height = l.iter().map(|&i| vsize[i].y).fold(0.0, f32::max);
        let mut left = 0f32;
        for (k, &node) in l.iter().enumerate() {
            if k > 0 {
                left += gap(l[k - 1], node);
            }
            x[node] = left;
            left += vsize[node].x;
        }
        layer_top[li] = top;
        layer_height[li] = height;
        top += height + V_GAP * 2.0;
    }
    // Pull nodes under the center of their predecessors, keeping the layer order.
    for _ in 0..4 {
        for l in layers.iter().skip(1) {
            let mut wanted: Vec<f32> = l
                .iter()
                .map(|&node| {
                    let preds = &vpreds[node];
                    if preds.is_empty() {
                        x[node]
                    } else {
                        preds.iter().map(|&a| x[a] + vsize[a].x / 2.0).sum::<f32>()
                            / preds.len() as f32
                            - vsize[node].x / 2.0
                    }
                })
                .collect();
            // Remove overlaps once pushing right and once pushing left, then average the
            // two. Both satisfy the spacing constraints, so their average does too, and
            // the layout no longer drifts to one side.
            let mut right = wanted.clone();
            for i in 1..l.len() {
                let min = right[i - 1] + vsize[l[i - 1]].x + gap(l[i - 1], l[i]);
                right[i] = right[i].max(min);
            }
            for i in (0..l.len().saturating_sub(1)).rev() {
                let max = wanted[i + 1] - vsize[l[i]].x - gap(l[i], l[i + 1]);
                wanted[i] = wanted[i].min(max);
            }
            for (i, &node) in l.iter().enumerate() {
                x[node] = (wanted[i] + right[i]) / 2.0;
            }
        }
    }
    let min_x = x.iter().copied().fold(f32::INFINITY, f32::min);
    for v in &mut x {
        *v -= min_x;
    }

    let nodes: Vec<Rect> = (0..n)
        .map(|i| Rect::from_min_size(Pos2::new(x[i], layer_top[layer[i]]), sizes[i]))
        .collect();
    let mut bounds = nodes.iter().fold(Rect::NOTHING, |acc, r| acc.union(*r));

    // 5. Edge routes. Out-edges leave a node spread along its bottom; forward edges pass
    // through their dummy waypoints with right-angle bends.
    let mut paths = Vec::with_capacity(edges.len());
    let mut back_lane = 0f32;
    let mut outs = vec![0usize; n];
    let mut out_index = vec![0usize; edges.len()];
    for (e, &(a, _)) in edges.iter().enumerate() {
        out_index[e] = outs[a];
        outs[a] += 1;
    }
    for (e, &(a, b)) in edges.iter().enumerate() {
        let src = nodes[a];
        let dst = nodes[b];
        let start_x =
            src.left() + src.width() * (out_index[e] as f32 + 1.0) / (outs[a] as f32 + 1.0);
        let start = Pos2::new(start_x, src.bottom());
        let end = Pos2::new(dst.center().x, dst.top());
        let points = if back[e] {
            back_lane += 1.0;
            let lane = bounds.left() - 1.5 * back_lane;
            vec![
                start,
                Pos2::new(start.x, start.y + V_GAP * 0.5),
                Pos2::new(lane, start.y + V_GAP * 0.5),
                Pos2::new(lane, end.y - V_GAP * 0.5),
                Pos2::new(end.x, end.y - V_GAP * 0.5),
                end,
            ]
        } else {
            let mut waypoints = vec![start];
            for &d in &chains[e] {
                let cx = x[d] + 0.5;
                let li = vlayer[d];
                waypoints.push(Pos2::new(cx, layer_top[li]));
                waypoints.push(Pos2::new(cx, layer_top[li] + layer_height[li]));
            }
            waypoints.push(end);
            orthogonal(&waypoints)
        };
        for p in &points {
            bounds = bounds.union(Rect::from_min_size(*p, Vec2::ZERO));
        }
        paths.push(EdgePath {
            from: a,
            to: b,
            points,
            back: back[e],
        });
    }

    Layout {
        nodes,
        edges: paths,
        bounds,
    }
}

/// Joins waypoints with horizontal and vertical segments, bending halfway between them.
fn orthogonal(waypoints: &[Pos2]) -> Vec<Pos2> {
    let mut out = vec![waypoints[0]];
    for pair in waypoints.windows(2) {
        let (p, q) = (pair[0], pair[1]);
        if (p.x - q.x).abs() > 0.01 {
            let mid = (p.y + q.y) / 2.0;
            out.push(Pos2::new(p.x, mid));
            out.push(Pos2::new(q.x, mid));
        }
        out.push(q);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sizes(n: usize) -> Vec<Vec2> {
        vec![Vec2::new(10.0, 4.0); n]
    }

    #[test]
    fn if_else_diamond() {
        // 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3
        let l = layout(&sizes(4), &[(0, 1), (0, 2), (1, 3), (2, 3)], 0);
        assert!(l.nodes[0].top() < l.nodes[1].top());
        assert_eq!(
            l.nodes[1].top(),
            l.nodes[2].top(),
            "both branches on one layer"
        );
        assert!(l.nodes[3].top() > l.nodes[1].top());
        assert!(!l.nodes[1].intersects(l.nodes[2]), "no overlap");
        assert!(l.edges.iter().all(|e| !e.back));
    }

    #[test]
    fn loops_have_back_edges() {
        // 0 -> 1 -> 2 -> 1 (loop), 1 -> 3
        let l = layout(&sizes(4), &[(0, 1), (1, 2), (2, 1), (1, 3)], 0);
        let back: Vec<_> = l.edges.iter().filter(|e| e.back).collect();
        assert_eq!(back.len(), 1);
        assert_eq!((back[0].from, back[0].to), (2, 1));
        assert!(l.nodes[2].top() > l.nodes[1].top());
    }

    #[test]
    fn handles_self_loop_unreachable_and_empty() {
        let l = layout(&sizes(3), &[(0, 0), (0, 1)], 0);
        assert_eq!(l.nodes.len(), 3);
        assert!(l.edges[0].back);
        assert!(layout(&[], &[], 0).nodes.is_empty());
    }

    #[test]
    fn long_edges_go_around_blocks() {
        // 0 -> 1 -> 2 -> 3 and a long edge 0 -> 3 that skips two layers.
        let l = layout(&sizes(4), &[(0, 1), (1, 2), (2, 3), (0, 3)], 0);
        let long = l.edges.iter().find(|e| e.from == 0 && e.to == 3).unwrap();
        for p in &long.points[1..long.points.len() - 1] {
            assert!(
                !l.nodes[1].contains(*p) && !l.nodes[2].contains(*p),
                "waypoint {p:?} inside a block"
            );
        }
    }
}

# FlowCanvas Agent Notes

## Change Reasons
- Flyout Trigger schedule parity: replaced plain text inputs with the same calendar, time, and timezone pickers used on the Trigger node, and added repeat enable/fields to match node behavior.
- Added quick-add overlays to palette/template cards and animated the workflow flyout open/close for smoother canvas interactions.
- Plan usage refresh now skips workspace-scoped requests for solo plans and the solo banner displays remaining monthly runs to avoid stale or blocked usage data.
- Dashboard now listens to workflow SSE updates, tracks `updated_at` versions, and surfaces conflict banners so workspace collaborators do not overwrite each other's saves.
- Workflow switches, new workflow creation, and run attempts now auto-save dirty graphs before proceeding so navigation and executions never drop pending edits.
- Added a global workflow auto-save hook that responds to integration OAuth connect requests so dirty graphs are persisted before redirecting away.
- Runs tab replaced by a separate Runs button that opens a sidebar drawer so the Designer tab stays active while run details live in the slide-out panel.
- Runs drawer only mounts when open, preventing it from overlaying or obscuring the canvas when closed.
- Runs button styled as a tab beside Designer and the runs panel now slides up from the bottom with animation to avoid blocking the node sidebar.
- Trigger run actions now pass the trigger id to manual run requests so multi-trigger workflows start from the selected entry instead of dispatching every trigger.
- Flyout node deletion now uses the same confirmation modal as the on-canvas nodes instead of the browser confirm dialog, keeping delete flows consistent across both surfaces.
- Flyout: clicking the dashed summary area on nodes now reliably keeps the flyout open (ignores the immediate empty selection event after an explicit open) while still allowing drag interactions.
- Flyout: node selection alone no longer opens the flyout; only the dashed hint surface triggers it on mouseup, preventing accidental opens when grabbing other parts of a node.
- Flyout: added a guard to ignore transient empty-selection events immediately after an explicit flyout open so the panel stays visible when clicking the designated dashed surface.
- Flyout: when opened from the dashed hint surface, the canvas pans smoothly to keep the activated node visible beside the flyout instead of being covered.
- Asana flyout now receives the normalized plan tier from the canvas controller so workspace plans skip the solo-only upgrade notice while keeping solo gating intact.
- Asana canvas nodes now pass the normalized plan tier into the node controller so the solo-only upgrade banner no longer appears for workspace plans when viewing the node on the canvas.
- Added Notion action palette entry plus trigger flyout controls (connection + database pickers) so Notion workflows can be configured alongside existing triggers and actions.
- Notion trigger fetch hooks drop the static `errorMessage` dependency to satisfy hooks lint while keeping error mapping intact.
- Webhook trigger flyout now initializes and requires an event_type value, and workflow saves are blocked when webhook triggers are missing it.
- Removed legacy webhook action normalization/aliases from the canvas so obsolete webhook action nodes are no longer recognized in the editor.
- Manifest action inputs now render number/boolean/string[]/object fields with typed parsing, JSON validation, and min/max-aware numeric controls.

## Notes
- Pickers are locally stateful and wrapped in useMemo/useCallback with click-outside + Escape handling to avoid React Flow re-render loops.
- Schedule changes patch node data via `updateNodeData` with shallow merges; removing repeat sets `repeat: undefined` to clear it without extra writes.

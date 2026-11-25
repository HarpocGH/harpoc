import { MAX_RENDER_SLOT_OCCURRENCES } from "./constants.js";
import { isValidHandle } from "./handle.js";

/** A render template's text pieces and slot handles, in order: one piece more than slots. */
export interface RenderTemplate {
  pieces: string[];
  slots: string[];
}

/**
 * A render template (design 5 § 6.2): a slot is `{{secret://name}}` or
 * `{{secret://project/name}}`, any other `{{` refuses the template, `}}` alone is
 * text, and nothing is normalized. `null` for a refused template or one of more
 * than `MAX_RENDER_SLOT_OCCURRENCES` slots, a repeated handle counted each time.
 */
export function parseRenderTemplate(text: string): RenderTemplate | null {
  const pieces: string[] = [];
  const slots: string[] = [];
  let from = 0;
  let open = text.indexOf("{{");
  while (open >= 0) {
    const close = text.indexOf("}}", open + 2);
    if (close < 0) return null;
    const handle = text.slice(open + 2, close);
    if (!isValidHandle(handle)) return null;
    pieces.push(text.slice(from, open));
    slots.push(handle);
    if (slots.length > MAX_RENDER_SLOT_OCCURRENCES) return null;
    from = close + 2;
    open = text.indexOf("{{", from);
  }
  pieces.push(text.slice(from));
  return { pieces, slots };
}

/** Each slot handle once, in the order of its first occurrence. */
export function distinctRenderSlots(template: RenderTemplate): string[] {
  return [...new Set(template.slots)];
}

/** One slot and nothing beside it: the whole file is the one value. */
export function isSingleSlotTemplate(template: RenderTemplate): boolean {
  return template.slots.length === 1 && template.pieces[0] === "" && template.pieces[1] === "";
}

/** Fits flags into the three slots. Alone the chip spans them all; beside other flags it drops
 *  its glyph to take two. More flags than free slots show all but one and a ⋯ for the rest:
 *  exactly as many as slots are all shown, since ⋯ would take the slot it frees. */
export function packFlags<F extends { glyph: string }>(items: F[]) {
  const chip = items[0]?.glyph === '⇅' ? items[0] : null
  const others = chip ? items.slice(1) : items
  const slots = chip ? 1 : 3
  const shown = others.length > slots ? others.slice(0, slots - 1) : others
  return { chip, others, shown, rest: others.slice(shown.length) }
}

// Single source of truth for Memory Graph node-kind colours. Previously
// duplicated as two independently-hand-maintained maps (WebGLMemoryGraph's
// float-tuple NODE_COLOURS for the WebGL shader, Memory.tsx's hex
// kindColours for the legend swatches) — a classic drift risk, since
// nothing enforced the two ever agreeing. Both now derive from this file.
//
// Palette is the dataviz skill's 8-hue validated categorical order,
// extended with one additional hue for Dendrite's 9th node kind, and
// re-validated as a full 9-slot set against this app's actual dark canvas
// surface (#050807, see styles.css's .memory-graph-stage) rather than the
// skill's generic dark default:
//
//   node scripts/validate_palette.js \
//     "#3987e5,#d95926,#199e70,#c98500,#d55181,#008300,#9085e9,#e66767,#12a3a3" \
//     --mode dark --surface "#050807"
//   -> ALL CHECKS PASS (lightness band, chroma floor, adjacent CVD >= 8.0,
//      adjacent normal-vision >= 15, contrast >= 3:1)
//
// This is the *adjacent*-pair guarantee (the fixed legend order below never
// changes) — a graph can bring any two kinds into visual proximity, and no
// 9-hue categorical set clears the stricter all-pairs floor (the skill's
// own palette caps all-pairs validation at 3 slots); node size-by-degree
// and the kind legend/filter are the secondary encoding that carries
// identity the rest of the way, per the skill's relief rule.
export const KIND_ORDER = [
  'process',
  'file',
  'host',
  'network_endpoint',
  'service',
  'user',
  'container',
  'incident',
  'threat',
] as const

export const KIND_COLOURS_HEX: Record<string, string> = {
  process: '#3987e5',
  file: '#d95926',
  host: '#199e70',
  network_endpoint: '#c98500',
  service: '#d55181',
  user: '#008300',
  container: '#9085e9',
  incident: '#e66767',
  threat: '#12a3a3',
}

export const DEFAULT_KIND_COLOUR_HEX = '#96a39b'

function hexToRgb01(hex: string): [number, number, number] {
  const value = hex.replace('#', '')
  const r = parseInt(value.slice(0, 2), 16) / 255
  const g = parseInt(value.slice(2, 4), 16) / 255
  const b = parseInt(value.slice(4, 6), 16) / 255
  return [r, g, b]
}

export const KIND_COLOURS_RGB01: Record<string, [number, number, number]> = Object.fromEntries(
  Object.entries(KIND_COLOURS_HEX).map(([kind, hex]) => [kind, hexToRgb01(hex)]),
)

export const DEFAULT_KIND_COLOUR_RGB01 = hexToRgb01(DEFAULT_KIND_COLOUR_HEX)

export function kindColourHex(kind: string): string {
  return KIND_COLOURS_HEX[kind] ?? DEFAULT_KIND_COLOUR_HEX
}

export function kindColourRgb01(kind: string): [number, number, number] {
  return KIND_COLOURS_RGB01[kind] ?? DEFAULT_KIND_COLOUR_RGB01
}

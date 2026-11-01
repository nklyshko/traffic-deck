import type { Tone } from './format'

export interface LogLine { time: string; message: string; tone: Tone | null; run: boolean }

const TIME = /^(\d{4}[/-]\d{2}[/-]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}(?::?\d{2})?)?)\s*/
const SEVERITY = /\b(error|fatal|panic|traceback|warn|warning|info|debug|trace)\b/i
const TONES: Record<string, Tone> = {
  error: 'red', fatal: 'red', panic: 'red', traceback: 'red', warn: 'amber', warning: 'amber', info: 'blue', debug: 'grey', trace: 'grey',
}

export function classifyLogLine(line: string): LogLine {
  if (/^===.*===\s*$/.test(line)) return { time: '', message: line, tone: null, run: true }
  const time = TIME.exec(line)?.[1] ?? ''
  const message = time ? line.slice(TIME.exec(line)![0].length) : line
  const word = SEVERITY.exec(message)?.[1].toLowerCase()
  return { time, message, tone: word ? TONES[word] : null, run: false }
}

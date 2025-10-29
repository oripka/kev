import { consola } from 'consola'
import type { ConsolaInstance } from 'consola'
import { colors, stripAnsi } from 'consola/utils'

const pad = (value: number) => value.toString().padStart(2, '0')

const formatTimestamp = (date: Date) =>
  `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`

type ProgressMode = 'update' | 'append'

type ProgressOptions = {
  mode?: ProgressMode
}

export class CliLogger {
  private readonly instance: ConsolaInstance

  private progressActive = false

  private lastProgressWidth = 0

  constructor() {
    this.instance = consola.withDefaults({
      formatOptions: {
        colors: true,
        compact: false,
        date: false
      }
    })
  }

  info(message: string) {
    this.prepareForLog()
    this.instance.info(this.withTimestamp(message))
  }

  success(message: string) {
    this.prepareForLog()
    this.instance.success(this.withTimestamp(message))
  }

  warn(message: string) {
    this.prepareForLog()
    this.instance.warn(this.withTimestamp(message))
  }

  error(message: string) {
    this.prepareForLog()
    this.instance.error(this.withTimestamp(message))
  }

  log(message: string) {
    this.prepareForLog()
    this.instance.log(this.withTimestamp(message))
  }

  progress(message: string, options: ProgressOptions = {}) {
    const mode = options.mode ?? 'update'
    const formatted = this.withTimestamp(message)

    if (mode === 'append') {
      this.endProgress()
      this.instance.log(formatted)
      return
    }

    const visibleLength = stripAnsi(formatted).length
    const padding = this.lastProgressWidth > visibleLength
      ? ' '.repeat(this.lastProgressWidth - visibleLength)
      : ''

    process.stdout.write(`\r${formatted}${padding}`)
    this.progressActive = true
    this.lastProgressWidth = visibleLength
  }

  endProgress() {
    if (this.progressActive) {
      process.stdout.write('\n')
      this.progressActive = false
      this.lastProgressWidth = 0
    }
  }

  newline(count = 1) {
    this.endProgress()
    if (count > 0) {
      process.stdout.write('\n'.repeat(count))
    }
  }

  private prepareForLog() {
    this.endProgress()
  }

  private withTimestamp(message: string) {
    const timestamp = formatTimestamp(new Date())
    if (!message) {
      return colors.dim(`[${timestamp}]`)
    }
    return `${colors.dim(`[${timestamp}]`)} ${message}`
  }
}

export const logger = new CliLogger()

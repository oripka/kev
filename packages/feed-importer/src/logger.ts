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

  private interactiveOutput: boolean

  private progressActive = false

  private lastProgressWidth = 0

  private lastProgressMessage: string | null = null

  private pendingDrain = false

  private queuedProgress: { formatted: string; visibleLength: number } | null = null

  private drainTimeout: NodeJS.Timeout | null = null

  private readonly drainFallbackDelayMs = 1000

  constructor() {
    this.instance = consola.withDefaults({
      formatOptions: {
        colors: true,
        compact: false,
        date: false
      }
    })
    this.interactiveOutput = false
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
      this.lastProgressMessage = null
      this.endProgress()
      this.instance.log(formatted)
      return
    }

    if (formatted === this.lastProgressMessage) {
      return
    }

    this.lastProgressMessage = formatted
    this.instance.log(formatted)
  }

  endProgress() {
    this.progressActive = false
    this.lastProgressWidth = 0
    this.lastProgressMessage = null
  }

  newline(count = 1) {
    this.endProgress()
    if (count > 0) {
      for (let index = 0; index < count; index += 1) {
        this.instance.log('')
      }
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

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
    this.interactiveOutput =
      Boolean(process.stdout.isTTY) &&
      (process.env.TERM ?? '').toLowerCase() !== 'dumb' &&
      process.env.KEV_IMPORT_PROGRESS !== 'off'
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

    if (!this.interactiveOutput) {
      if (formatted === this.lastProgressMessage) {
        return
      }
      this.lastProgressMessage = formatted
      this.instance.log(formatted)
      return
    }

    if (formatted === this.lastProgressMessage) {
      return
    }

    const visibleLength = stripAnsi(formatted).length
    const padding =
      this.lastProgressWidth > visibleLength
        ? ' '.repeat(this.lastProgressWidth - visibleLength)
        : ''

    this.writeProgress(formatted, visibleLength, padding)
  }

  endProgress() {
    if (this.progressActive && this.interactiveOutput) {
      process.stdout.write('\n')
    }
    this.clearDrainTimeout()
    this.pendingDrain = false
    this.queuedProgress = null
    this.progressActive = false
    this.lastProgressWidth = 0
    this.lastProgressMessage = null
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

  private clearDrainTimeout() {
    if (this.drainTimeout) {
      clearTimeout(this.drainTimeout)
      this.drainTimeout = null
    }
  }

  private scheduleDrainFallback() {
    if (this.drainTimeout) {
      return
    }
    this.drainTimeout = setTimeout(() => {
      this.drainTimeout = null
      if (!this.pendingDrain) {
        return
      }
      this.pendingDrain = false
      const queued = this.queuedProgress
      this.queuedProgress = null
      // Disable interactive progress updates after a drain timeout to avoid repeated stalls.
      const fallbackMessage = queued?.formatted ?? this.lastProgressMessage ?? ''
      if (fallbackMessage) {
        this.disableInteractiveProgress(fallbackMessage)
      } else {
        this.disableInteractiveProgress('')
      }
    }, this.drainFallbackDelayMs)
    this.drainTimeout.unref?.()
  }

  private writeProgress(formatted: string, visibleLength: number, padding: string) {
    if (!this.interactiveOutput) {
      return
    }

    if (this.pendingDrain) {
      this.queuedProgress = { formatted, visibleLength }
      return
    }

    const output = `\r${formatted}${padding}`
    const wrote = process.stdout.write(output)

    this.progressActive = true
    this.lastProgressWidth = visibleLength
    this.lastProgressMessage = formatted

    if (!wrote) {
      this.disableInteractiveProgress(formatted)
      return
    }

    this.clearDrainTimeout()
  }

  private withTimestamp(message: string) {
    const timestamp = formatTimestamp(new Date())
    if (!message) {
      return colors.dim(`[${timestamp}]`)
    }
    return `${colors.dim(`[${timestamp}]`)} ${message}`
  }

  private disableInteractiveProgress(formatted: string) {
    if (!this.interactiveOutput) {
      if (formatted) {
        this.instance.log(formatted)
        this.lastProgressMessage = formatted
      }
      return
    }

    this.clearDrainTimeout()
    this.pendingDrain = false
    this.queuedProgress = null
    this.progressActive = false
    this.lastProgressWidth = 0
    this.interactiveOutput = false
    if (formatted) {
      this.lastProgressMessage = formatted
      this.instance.log(formatted)
    } else {
      this.lastProgressMessage = null
    }
  }
}

export const logger = new CliLogger()

import type { ClassificationPhase, ClassificationProgress } from '~/types'

type ProgressPatch = Partial<ClassificationProgress>

declare global {
  // eslint-disable-next-line no-var
  var __kevClassificationProgress: ClassificationProgress | undefined
}

const defaultState: ClassificationProgress = {
  phase: 'idle',
  completed: 0,
  total: 0,
  message: '',
  startedAt: null,
  updatedAt: null,
  error: null
}

const getState = (): ClassificationProgress => {
  if (!globalThis.__kevClassificationProgress) {
    globalThis.__kevClassificationProgress = { ...defaultState }
  }

  return globalThis.__kevClassificationProgress
}

const commit = (patch: ProgressPatch) => {
  const current = getState()
  const timestamp = new Date().toISOString()

  const nextPhase = patch.phase ?? current.phase
  const startedAt =
    nextPhase !== 'idle' && current.phase === 'idle'
      ? timestamp
      : nextPhase === 'idle'
        ? null
        : current.startedAt

  globalThis.__kevClassificationProgress = {
    ...current,
    ...patch,
    updatedAt: timestamp,
    startedAt,
    ...(nextPhase === 'idle'
      ? {
          phase: 'idle' as ClassificationPhase,
          completed: 0,
          total: 0,
          message: '',
          error: null
        }
      : {}),
    phase: nextPhase
  }
}

export const resetClassificationProgress = () => {
  globalThis.__kevClassificationProgress = { ...defaultState }
}

export const startClassificationProgress = (message: string, total: number) => {
  commit({
    phase: 'preparing',
    message,
    completed: 0,
    total,
    error: null
  })
}

export const setClassificationPhase = (
  phase: ClassificationPhase,
  payload: ProgressPatch = {}
) => {
  commit({
    ...payload,
    phase
  })
}

export const updateClassificationProgress = (
  completed: number,
  total: number,
  message?: string
) => {
  commit({
    phase: 'rebuilding',
    completed,
    total,
    message: message ?? getState().message
  })
}

export const completeClassificationProgress = (message: string) => {
  commit({
    phase: 'complete',
    completed: getState().total,
    message,
    error: null
  })
}

export const failClassificationProgress = (message: string) => {
  commit({
    phase: 'error',
    message,
    error: message
  })
}

export const getClassificationProgress = (): ClassificationProgress => {
  return { ...getState() }
}

export type Task<T> = () => Promise<T>

export const createTaskQueue = (concurrency: number) => {
  if (!Number.isInteger(concurrency) || concurrency < 1) {
    throw new RangeError('Concurrency must be a positive integer')
  }

  let activeCount = 0
  const queue: Array<() => void> = []

  const dequeue = () => {
    while (activeCount < concurrency && queue.length > 0) {
      const nextTask = queue.shift()
      if (!nextTask) {
        continue
      }
      activeCount += 1
      nextTask()
    }
  }

  return async <T>(task: Task<T>): Promise<T> => {
    return await new Promise<T>((resolve, reject) => {
      const run = () => {
        Promise.resolve()
          .then(task)
          .then(resolve, reject)
          .finally(() => {
            activeCount -= 1
            dequeue()
          })
      }

      queue.push(run)
      dequeue()
    })
  }
}

type ConcurrencyOptions = {
  onProgress?: (completed: number, total: number) => void
}

export const mapWithConcurrency = async <T, R>(
  items: readonly T[],
  concurrency: number,
  iteratee: (item: T, index: number) => Promise<R>,
  options: ConcurrencyOptions = {}
): Promise<R[]> => {
  if (items.length === 0) {
    return []
  }

  const runTask = createTaskQueue(concurrency)
  const results = new Array<R>(items.length)
  const total = items.length
  let completed = 0
  const { onProgress } = options

  await Promise.all(
    items.map((item, index) =>
      runTask(async () => {
        const result = await iteratee(item, index)
        results[index] = result
        completed += 1
        if (onProgress) {
          onProgress(completed, total)
        }
        return result
      })
    )
  )

  return results
}

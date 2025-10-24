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

export const mapWithConcurrency = async <T, R>(
  items: readonly T[],
  concurrency: number,
  iteratee: (item: T, index: number) => Promise<R>
): Promise<R[]> => {
  if (items.length === 0) {
    return []
  }

  const runTask = createTaskQueue(concurrency)
  const results = new Array<R>(items.length)

  await Promise.all(
    items.map((item, index) =>
      runTask(async () => {
        const result = await iteratee(item, index)
        results[index] = result
        return result
      })
    )
  )

  return results
}

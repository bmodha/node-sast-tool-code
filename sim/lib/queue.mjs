export function drain(jobs, handle) {
  const queue = [...jobs];
  const results = [];
  while (queue.length) results.push(handle(queue.shift()));
  return results;
}

// One worker, one job at a time. wasm cannot be interrupted, so cancelling terminates the worker
// (dropping any warmed keys) and starts a fresh one; overlapping jobs are refused rather than queued
// so a slow proof can never pile up memory behind it. A job may report progress before it ends.
export class JobRunner {
  #worker = null;
  #job = null;
  #nextId = 0;

  constructor(url) {
    this.url = url;
    this.#spawn();
  }

  get busy() {
    return this.#job !== null;
  }

  #spawn() {
    this.#worker = new Worker(this.url, { type: "module" });
    this.#worker.onmessage = ({ data }) => {
      const job = this.#job;
      if (!job || data.id !== job.id) return;
      if (data.progress) return job.onProgress?.(data.progress);
      this.#job = null;
      if (data.ok) job.resolve(data);
      else job.reject(new Error(data.error));
    };
    this.#worker.onerror = (event) => this.#fail(new Error(event.message || "worker crashed"));
  }

  #fail(error) {
    const job = this.#job;
    this.#job = null;
    this.#worker.terminate();
    this.#spawn();
    job?.reject(error);
  }

  run(op, args = {}, onProgress = null) {
    if (this.#job) return Promise.reject(new Error("another job is still running"));
    return new Promise((resolve, reject) => {
      const id = this.#nextId++;
      this.#job = { id, resolve, reject, onProgress };
      this.#worker.postMessage({ id, op, args });
    });
  }

  cancel() {
    if (!this.#job) return false;
    this.#fail(new Error("cancelled"));
    return true;
  }
}

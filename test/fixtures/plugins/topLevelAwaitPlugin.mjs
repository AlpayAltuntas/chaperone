// Uses top-level await, which a synchronously loaded plugin can't.
await Promise.resolve();
export default {};

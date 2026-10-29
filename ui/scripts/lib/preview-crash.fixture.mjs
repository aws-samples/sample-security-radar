// Fixture for preview.test.mjs: start preview, then crash — the port must be freed by the exit handlers.
import { startVite } from './preview.mjs';
const port = Number(process.argv[2]);
const { child } = await startVite([], { cwd: process.cwd(), port });
console.log(`UP ${child.pid}`); // pgid, so the test can reap the group even when cleanup is broken (mutation UP1)
setTimeout(() => { throw new Error('simulated crash'); }, 10);

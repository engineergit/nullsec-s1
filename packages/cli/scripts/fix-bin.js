import { chmod, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const binPath = resolve("dist/index.js");
const source = await readFile(binPath, "utf8");

if (!source.startsWith("#!/usr/bin/env node")) {
  await writeFile(binPath, `#!/usr/bin/env node\n${source}`, "utf8");
}

await chmod(binPath, 0o755);

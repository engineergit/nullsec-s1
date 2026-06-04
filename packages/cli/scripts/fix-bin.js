import { chmod, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

for (const bin of ["cli.js", "mcp.js"]) {
  const binPath = resolve("dist", bin);
  const source = await readFile(binPath, "utf8");

  if (!source.startsWith("#!/usr/bin/env node")) {
    await writeFile(binPath, `#!/usr/bin/env node\n${source}`, "utf8");
  }

  await chmod(binPath, 0o755);
}

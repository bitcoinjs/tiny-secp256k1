// eslint-disable-next-line @typescript-eslint/no-var-requires
const fs = require("fs");

const location = process.argv[2];
const text = fs.readFileSync(location, "utf-8");
const package = JSON.parse(text);

const fields = [
  "name",
  "version",
  "description",
  "homepage",
  "bugs",
  "repository",
  "license",
  "main",
  "browser",
  "types",
  "scripts",
  "engines",
];
for (const key of Object.keys(package)) {
  if (!fields.includes(key)) {
    delete package[key];
  }
}
package.scripts = { install: "node on-install.js" };

fs.writeFileSync(location, JSON.stringify(package, null, 2));

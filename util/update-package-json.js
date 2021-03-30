import fs from "fs";

const location = process.argv[2];
const text = fs.readFileSync(location, "utf-8");
const pkg = JSON.parse(text);

const fields = [
  "name",
  "version",
  "description",
  "homepage",
  "bugs",
  "repository",
  "license",
  "type",
  "main",
  "browser",
  "types",
  "scripts",
  "engines",
];
for (const key of Object.keys(pkg)) {
  if (!fields.includes(key)) {
    delete pkg[key];
  }
}
pkg.scripts = { install: "node on-install.js" };

fs.writeFileSync(location, JSON.stringify(pkg, null, 2));

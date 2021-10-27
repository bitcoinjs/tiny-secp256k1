import { createReadStream } from "fs";
import { URL } from "url";
import browserRun from "browser-run";

createReadStream(new URL("browser/index.js", import.meta.url), "utf8")
  .pipe(
    browserRun({
      static: "tests/browser",
      sandbox: false,
    })
  )
  .pipe(process.stdout);

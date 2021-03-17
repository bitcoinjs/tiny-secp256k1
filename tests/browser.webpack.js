import { createRequire } from "module";
import { URL } from "url";
import webpack from "webpack";

const require = createRequire(import.meta.url);

export default {
  target: "web",
  mode: "development",
  entry: "./tests/index.js",
  output: {
    path: new URL("browser", import.meta.url).pathname,
    filename: "index.js",
  },
  experiments: {
    asyncWebAssembly: true,
  },
  plugins: [
    new webpack.ProvidePlugin({
      process: "process/browser.js",
    }),
  ],
  resolve: {
    fallback: {
      buffer: require.resolve("buffer"),
      fs: false,
      path: require.resolve("path-browserify"),
      stream: require.resolve("stream-browserify"),
    },
  },
};

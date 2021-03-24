// eslint-disable-next-line @typescript-eslint/no-var-requires
const path = require("path");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const webpack = require("webpack");

module.exports = {
  target: "web",
  mode: "development",
  entry: "./tests/index.js",
  output: {
    path: path.resolve(__dirname, "browser"),
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

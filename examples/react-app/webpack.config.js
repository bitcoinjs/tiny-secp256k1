// eslint-disable-next-line @typescript-eslint/no-var-requires
const path = require("path");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const webpack = require("webpack");

module.exports = {
  mode: process.env.NODE_ENV || "development",
  entry: "./index.js",
  module: {
    rules: [
      {
        test: /\.(js|jsx)$/,
        exclude: /node_modules/,
        use: {
          loader: "babel-loader",
          options: {
            presets: ["@babel/preset-env", "@babel/preset-react"],
          },
        },
      },
    ],
  },
  output: {
    filename: "bundle.js",
    path: path.resolve(__dirname, "dist"),
  },
  devServer: {
    contentBase: path.resolve(__dirname, "dist"),
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
      crypto: require.resolve("crypto-browserify"),
      process: require.resolve("process/browser"),
      stream: require.resolve("stream-browserify"),
    },
  },
};

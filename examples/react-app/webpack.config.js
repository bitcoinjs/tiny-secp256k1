import { URL } from "url";
import webpack from "webpack";

export default {
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
            presets: ["@babel/preset-react"],
          },
        },
      },
    ],
  },
  output: {
    filename: "bundle.js",
    path: new URL("dist", import.meta.url).pathname,
  },
  devServer: {
    static: new URL("dist", import.meta.url).pathname,
  },
  experiments: {
    asyncWebAssembly: true,
  },
  plugins: [
    new webpack.ProvidePlugin({
      process: "process/browser.js",
    }),
  ],
};

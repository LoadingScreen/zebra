const CopyWebpackPlugin = require("copy-webpack-plugin");
const path = require('path');

module.exports = {
  entry: "./bootstrap.js",
  output: {
    path: path.resolve(__dirname, "dist"),
    filename: "bootstrap.js",
  },
  mode: "production",
  plugins: [
    new CopyWebpackPlugin([
      'index.html',
      'manifest.json',
      'favicon.ico',
      'android-chrome-192x192.png',
      'android-chrome-512x512.png'
    ])
  ],
};
